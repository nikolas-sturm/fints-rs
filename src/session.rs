//! Persistable FinTS session state.
//!
//! A FinTS client is expected to remember what the bank told it: the
//! customer system ID (HKSYN), the bank parameter data (BPD) and the user
//! parameter data (UPD), together with their versions. HKVVB then announces
//! the cached versions and the bank only resends BPD/UPD when they changed.
//! hbci4java keeps all of this in its passport file; [`SessionState`] is the
//! equivalent here.
//!
//! A stable system ID matters: a new one per run makes some banks demand
//! extra SCA. Store the state after every successful run and pass it back
//! in on the next one.
//!
//! The state is not a credential (no PIN, no TAN), but it identifies the
//! user to the bank. Store it encrypted.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{FinTSError, Result};
use crate::parser::{self, RawSegment};
use crate::protocol::BankParams;
use crate::serializer;
use crate::types::*;

/// Current serialization format of [`SessionState`].
pub const SESSION_STATE_FORMAT: u32 = 1;

/// Everything worth keeping between two runs for one user at one bank.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Format version, for future migrations.
    pub format: u32,
    /// Bank the state belongs to.
    pub blz: Blz,
    /// User the state belongs to. Updated when the bank reports 3072.
    pub user_id: UserId,
    /// Customer system ID assigned by the bank (HISYN). "0" = none yet.
    pub system_id: SystemId,
    /// BPD version announced in HKVVB.
    pub bpd_version: u16,
    /// UPD version announced in HKVVB.
    pub upd_version: u16,
    /// Raw BPD segments in FinTS wire format, as the bank sent them.
    #[serde(with = "wire_segments")]
    bpd: Vec<RawSegment>,
    /// Raw UPD segments in FinTS wire format, as the bank sent them.
    #[serde(with = "wire_segments")]
    upd: Vec<RawSegment>,
    /// Security function (TAN method) to use, e.g. "902" for pushTAN.
    pub tan_method: Option<SecurityFunction>,
    /// TAN medium name, for methods that require one.
    pub tan_medium: Option<TanMediumName>,
    /// Security functions the bank last allowed for this user (code 3920).
    #[serde(default)]
    pub allowed_security_functions: Vec<SecurityFunction>,
    /// When the bank last reported (3072) that the user ID changed, the new
    /// ID was written to `user_id`; this keeps the old one so the caller can
    /// update its stored credentials.
    #[serde(default)]
    pub previous_user_id: Option<UserId>,
    /// Last time this state was produced.
    pub updated_at: DateTime<Utc>,
}

impl SessionState {
    /// Empty state for a user at a bank: no system ID, no BPD/UPD.
    pub fn new(blz: &Blz, user_id: &UserId) -> Self {
        Self {
            format: SESSION_STATE_FORMAT,
            blz: blz.clone(),
            user_id: user_id.clone(),
            system_id: SystemId::unassigned(),
            bpd_version: 0,
            upd_version: 0,
            bpd: Vec::new(),
            upd: Vec::new(),
            tan_method: None,
            tan_medium: None,
            allowed_security_functions: Vec::new(),
            previous_user_id: None,
            updated_at: Utc::now(),
        }
    }

    /// Start from a known system ID (e.g. migrating from an older store).
    pub fn with_system_id(mut self, system_id: &SystemId) -> Self {
        self.system_id = system_id.clone();
        self
    }

    /// Prefer this TAN method (security function) when the bank allows it.
    pub fn with_tan_method(mut self, security_function: &SecurityFunction) -> Self {
        self.tan_method = Some(security_function.clone());
        self
    }

    /// Use this TAN medium (device name) for methods that require one.
    pub fn with_tan_medium(mut self, medium: &TanMediumName) -> Self {
        self.tan_medium = Some(medium.clone());
        self
    }

    /// True when the state holds a system ID and a BPD with TAN methods, so a
    /// new dialog can skip the synchronization dialog.
    pub fn can_skip_sync(&self) -> bool {
        self.system_id.is_assigned() && self.bpd_version > 0 && !self.bpd.is_empty()
    }

    /// TAN methods announced in the cached BPD.
    pub fn tan_methods(&self) -> Vec<TanMethod> {
        self.to_params().tan_methods
    }

    /// Accounts listed in the cached UPD.
    pub fn accounts(&self) -> Vec<SepaAccount> {
        self.to_params().accounts_from_upd
    }

    /// Drop the system ID and cached BPD/UPD, e.g. after the bank rejected
    /// the system ID (9391). The next run synchronizes from scratch.
    pub fn reset(&mut self) {
        let fresh = Self::new(&self.blz, &self.user_id);
        let (tan_method, tan_medium) = (self.tan_method.take(), self.tan_medium.take());
        *self = Self { tan_method, tan_medium, ..fresh };
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| FinTSError::Serialize(format!("session state: {e}")))
    }

    /// Deserialize from JSON produced by [`SessionState::to_json`].
    pub fn from_json(json: &str) -> Result<Self> {
        let state: Self = serde_json::from_str(json).map_err(|e| FinTSError::Parse(format!("session state: {e}")))?;
        if state.format > SESSION_STATE_FORMAT {
            return Err(FinTSError::Parse(format!(
                "session state format {} is newer than supported ({})",
                state.format, SESSION_STATE_FORMAT
            )));
        }
        Ok(state)
    }

    /// Rebuild bank parameters from the cached BPD/UPD.
    pub(crate) fn to_params(&self) -> BankParams {
        let mut params = BankParams::new();
        params.set_bpd(self.bpd.clone());
        params.set_upd(self.upd.clone());
        // Versions are what we announce in HKVVB; keep the stored ones even if
        // a segment was lost, so the bank resends rather than us guessing.
        params.bpd_version = if self.bpd.is_empty() { 0 } else { self.bpd_version };
        params.upd_version = if self.upd.is_empty() { 0 } else { self.upd_version };
        params.allowed_security_functions = self.allowed_security_functions.clone();
        params.preferred_security_function = self.tan_method.clone();
        params.selected_tan_medium = self.tan_medium.clone();
        params.select_security_function();
        params
    }

    /// Capture the state after a dialog.
    pub(crate) fn capture(blz: &Blz, user_id: &UserId, system_id: &SystemId, params: &BankParams) -> Self {
        let (user_id, previous_user_id) = match &params.changed_user_id {
            Some(new_id) if new_id != user_id => (new_id.clone(), Some(user_id.clone())),
            _ => (user_id.clone(), None),
        };
        let pin_only = SecurityFunction::pin_only();
        Self {
            format: SESSION_STATE_FORMAT,
            blz: blz.clone(),
            user_id,
            system_id: system_id.clone(),
            bpd_version: params.bpd_version,
            upd_version: params.upd_version,
            bpd: params.bpd_segments.clone(),
            upd: params.upd_segments.clone(),
            tan_method: Some(params.selected_security_function.clone()).filter(|sf| *sf != pin_only),
            tan_medium: params.selected_tan_medium.clone(),
            allowed_security_functions: params.allowed_security_functions.clone(),
            previous_user_id,
            updated_at: Utc::now(),
        }
    }
}

/// Serialize segments as their FinTS wire form (ISO-8859-1 mapped 1:1 to
/// chars), which is compact, diffable, and exactly what the bank sent.
mod wire_segments {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(segments: &[RawSegment], s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut out = Vec::new();
        for seg in segments {
            out.extend(serializer::serialize_segment(&seg.degs).map_err(serde::ser::Error::custom)?);
        }
        s.serialize_str(&out.iter().map(|&b| b as char).collect::<String>())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<RawSegment>, D::Error> {
        let text = String::deserialize(d)?;
        let bytes = text
            .chars()
            .map(|c| u8::try_from(u32::from(c)).map_err(|_| serde::de::Error::custom("non-Latin-1 char in segment data")))
            .collect::<std::result::Result<Vec<u8>, _>>()?;
        parser::parse_message(&bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BPD: &str = "HIBPA:6:3:4+78+280:12345678+Test Bank+1+1+300+500'\
        HIKAZS:10:7:4+1+1+1+365:J:N'HISALS:19:7:4+1+1+1'\
        HITANS:53:5:4+1+1+1+N:N:0:942:2:MTAN2:mobileTAN::mobile TAN:6:1:SMS:3:1:J:1:0:N:0:2:N:J:00:1:1'\
        HIPINS:54:1:4+1+1+1+5:20:6:Benutzer ID::HKKAZ:N:HKSAL:N:HKTAN:N'";
    const UPD: &str = "HIUPA:57:4:4+test1+3+0'\
        HIUPD:58:6:4+1::280:12345678+DE111234567800000001+test1++EUR+Fullname++Girokonto++HKSAL:1'";

    fn params() -> BankParams {
        let mut p = BankParams::new();
        p.set_bpd(parser::parse_message(BPD.as_bytes()).unwrap());
        p.set_upd(parser::parse_message(UPD.as_bytes()).unwrap());
        p.allowed_security_functions = vec![SecurityFunction::new("942")];
        p.select_security_function();
        p
    }

    #[test]
    fn capture_and_restore_roundtrip_through_json() {
        let state = SessionState::capture(
            &Blz::new("12345678"), &UserId::new("test1"), &SystemId::new("SYS;001"), &params(),
        );
        assert_eq!((state.bpd_version, state.upd_version), (78, 3));
        assert_eq!(state.tan_method, Some(SecurityFunction::new("942")));
        assert!(state.can_skip_sync());

        let json = state.to_json().unwrap();
        assert!(json.contains("HIBPA:6:3:4+78"), "BPD is stored in wire format: {json}");
        let restored = SessionState::from_json(&json).unwrap();

        let p = restored.to_params();
        assert_eq!((p.bpd_version, p.upd_version), (78, 3));
        assert_eq!(p.tan_methods.len(), 1);
        assert_eq!(p.selected_security_function, SecurityFunction::new("942"));
        assert_eq!(p.accounts_from_upd.len(), 1);
        assert_eq!(p.operation_tan_required.get(&SegmentType::new("HKKAZ")), Some(&false));
        assert_eq!(restored.system_id.as_str(), "SYS;001");
    }

    #[test]
    fn empty_state_requests_full_parameter_data() {
        let state = SessionState::new(&Blz::new("50010517"), &UserId::new("u"));
        assert!(!state.can_skip_sync());
        let p = state.to_params();
        assert_eq!((p.bpd_version, p.upd_version), (0, 0));
    }

    #[test]
    fn changed_user_id_is_carried_over() {
        let mut p = params();
        p.changed_user_id = Some(UserId::new("new-user"));
        let state = SessionState::capture(&Blz::new("1"), &UserId::new("old-user"), &SystemId::new("S"), &p);
        assert_eq!(state.user_id.as_str(), "new-user");
        assert_eq!(state.previous_user_id.as_ref().map(|u| u.as_str()), Some("old-user"));
    }

    #[test]
    fn reset_keeps_tan_preferences_only() {
        let mut state = SessionState::capture(&Blz::new("1"), &UserId::new("u"), &SystemId::new("S"), &params())
            .with_tan_medium(&TanMediumName::new("iPhone"));
        state.reset();
        assert!(!state.system_id.is_assigned());
        assert!(!state.can_skip_sync());
        assert_eq!(state.tan_medium.as_ref().map(|m| m.as_str()), Some("iPhone"));
        assert_eq!(state.tan_method, Some(SecurityFunction::new("942")));
    }

    #[test]
    fn rejects_newer_format() {
        let mut state = SessionState::new(&Blz::new("1"), &UserId::new("u"));
        state.format = SESSION_STATE_FORMAT + 1;
        let json = serde_json::to_string(&state).unwrap();
        assert!(SessionState::from_json(&json).is_err());
    }
}
