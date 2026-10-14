//! MT535 (Statement of Holdings) parser for HIWPD depot responses.
//!
//! HIWPD carries the depot statement as one binary data element containing a
//! SWIFT MT535 message. The parts a dashboard needs:
//!
//! ```text
//! :16R:GENL
//! :97A::SAFE//50010517/1234567890          depot (BLZ/number)
//! :98A::STAT//20260315                     statement date
//! :16S:GENL
//! :16R:FIN                                 one block per position
//! :35B:ISIN DE0005140008                   identification …
//! /DE/514000                                 … WKN …
//! DEUTSCHE BANK AG NA O.N.                   … name (may span lines)
//! :90B::MRKT//ACTU/EUR42,5                 price (ACTU = amount, 90A …/PRCT/ = percent)
//! :94B::PRIC//LMAR/XETR                    price source / exchange
//! :98A::PRIC//20260315                     price date (98C: with time)
//! :93B::AGGR//UNIT/100,                    quantity (UNIT = pieces, FAMT = face amount)
//! :19A::HOLD//EUR4250,                     market value of the position
//! :70E::HOLD//1STK++++20200101+            free text: line 1 type/dates,
//! 238,5+EUR                                  line 2 acquisition price + currency
//! :16S:FIN
//! -
//! ```
//!
//! Written from the SWIFT MT535 layout as used by German banks; field
//! choices cross-checked with hbci4java's GVWPDepotList and python-fints'
//! MT535_Miniparser. Unknown fields are ignored, never fatal.

use std::str::FromStr;

use chrono::NaiveDate;
use rust_decimal::Decimal;

use crate::types::*;

/// One `:TAG:value` field, continuation lines joined with `\n`.
struct Field<'a> {
    tag: &'a str,
    value: String,
}

fn fields(text: &str) -> Vec<Field<'_>> {
    let mut out: Vec<Field> = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix(':') {
            if let Some((tag, value)) = rest.split_once(':') {
                out.push(Field { tag, value: value.to_string() });
                continue;
            }
        }
        if line == "-" || line.is_empty() {
            continue;
        }
        if let Some(last) = out.last_mut() {
            last.value.push('\n');
            last.value.push_str(line);
        }
    }
    out
}

/// Split `:QUAL//rest` into (QUAL, rest).
fn qualified(value: &str) -> Option<(&str, &str)> {
    value.strip_prefix(':')?.split_once("//")
}

/// SWIFT amount: comma decimal, optional trailing comma, optional `N` sign.
fn amount(s: &str) -> Option<Decimal> {
    let s = s.trim();
    let (neg, digits) = match s.strip_prefix('N') {
        Some(d) => (true, d),
        None => (false, s),
    };
    let normalized = digits.replace(',', ".");
    let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);
    let v = Decimal::from_str(normalized).ok()?;
    Some(if neg { -v } else { v })
}

/// `EUR4250,` / `NEUR12,3` → (currency, amount).
fn currency_amount(s: &str) -> Option<(String, Decimal)> {
    let s = s.trim();
    let (neg, rest) = match s.strip_prefix('N') {
        Some(r) if r.len() > 3 && r[..3].bytes().all(|b| b.is_ascii_uppercase()) => (true, r),
        _ => (false, s),
    };
    if rest.len() < 4 || !rest.is_char_boundary(3) || !rest[..3].bytes().all(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let v = amount(&rest[3..])?;
    Some((rest[..3].to_string(), if neg { -v } else { v }))
}

fn date(s: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(s.get(..8)?, "%Y%m%d").ok()
}

#[derive(Default)]
struct Position {
    isin: Option<String>,
    wkn: Option<String>,
    name_lines: Vec<String>,
    price: Option<Decimal>,
    price_is_percent: bool,
    price_currency: Option<String>,
    price_date: Option<NaiveDate>,
    exchange: Option<String>,
    quantity: Option<Decimal>,
    quantity_is_face_amount: bool,
    market_value: Option<(String, Decimal)>,
    acquisition_price: Option<Decimal>,
    acquisition_currency: Option<String>,
}

impl Position {
    fn apply(&mut self, f: &Field<'_>) {
        match f.tag {
            "35B" => {
                for (i, line) in f.value.lines().enumerate() {
                    let line = line.trim();
                    if i == 0 {
                        if let Some(isin) = line.strip_prefix("ISIN ") {
                            self.isin = Some(isin.trim().to_string());
                            continue;
                        }
                    }
                    if let Some(rest) = line.strip_prefix('/') {
                        // "/DE/514000" — national code
                        if let Some((_, code)) = rest.split_once('/') {
                            self.wkn.get_or_insert_with(|| code.trim().to_string());
                            continue;
                        }
                    }
                    if !line.is_empty() {
                        self.name_lines.push(line.to_string());
                    }
                }
            }
            "90A" | "90B" => {
                if let Some((_, rest)) = qualified(&f.value) {
                    // PRCT/101,5 | ACTU/EUR42,5 | YIEL/… | DISC/…
                    if let Some(p) = rest.strip_prefix("PRCT/") {
                        self.price = amount(p);
                        self.price_is_percent = true;
                    } else if let Some(p) = rest.strip_prefix("ACTU/") {
                        if let Some((cur, v)) = currency_amount(p) {
                            self.price = Some(v);
                            self.price_currency = Some(cur);
                        }
                    }
                }
            }
            "98A" | "98C" => {
                if let Some(("PRIC", d)) = qualified(&f.value) {
                    self.price_date = date(d);
                }
            }
            "94B" => {
                if let Some(("PRIC", rest)) = qualified(&f.value) {
                    // LMAR/XETR, or e.g. "THEO/" with a narrative after the next slash
                    let source = rest.split_once('/').map_or(rest, |(_, s)| s).trim();
                    if !source.is_empty() {
                        self.exchange = Some(source.to_string());
                    }
                }
            }
            "93B" => {
                if let Some(("AGGR", rest)) = qualified(&f.value) {
                    if let Some((kind, q)) = rest.split_once('/') {
                        self.quantity = amount(q);
                        self.quantity_is_face_amount = kind == "FAMT";
                    }
                }
            }
            "19A" => {
                if let Some(("HOLD", rest)) = qualified(&f.value) {
                    self.market_value = currency_amount(rest);
                }
            }
            "70E" => {
                if let Some(("HOLD", text)) = qualified(&f.value) {
                    // Line 2: "2<price>+<currency>[+<interest>]"
                    for line in text.lines() {
                        if let Some(rest) = line.trim().strip_prefix('2') {
                            let mut parts = rest.split('+');
                            self.acquisition_price = parts.next().and_then(amount);
                            self.acquisition_currency = parts.next().filter(|c| c.len() == 3).map(str::to_string);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn into_holding(self, depot_id: Option<&str>) -> Option<SecurityHolding> {
        if self.isin.is_none() && self.wkn.is_none() {
            return None;
        }
        let quantity = self.quantity.unwrap_or(Decimal::ZERO);
        // Percent prices (bonds) apply to the face amount.
        let value_of = |price: Decimal| {
            if self.price_is_percent { quantity * price / Decimal::from(100) } else { quantity * price }
        };
        let (market_value, market_value_currency) = match &self.market_value {
            Some((cur, v)) => (Some(*v), Some(cur.clone())),
            None => (self.price.map(value_of), self.price_currency.clone()),
        };
        let acquisition_value = self.acquisition_price.map(value_of);
        let profit_loss = match (market_value, acquisition_value) {
            (Some(m), Some(a)) => Some(m - a),
            _ => None,
        };
        let name = self.name_lines.join(" ");

        let raw = serde_json::json!({
            "source": "MT535",
            "isin": self.isin,
            "wkn": self.wkn,
            "name": name,
            "quantity": quantity.to_string(),
            "quantity_type": if self.quantity_is_face_amount { "FAMT" } else { "UNIT" },
            "price": self.price.map(|p| p.to_string()),
            "price_type": if self.price_is_percent { "PRCT" } else { "ACTU" },
            "price_currency": self.price_currency,
            "price_date": self.price_date.map(|d| d.to_string()),
            "exchange": self.exchange,
            "market_value": market_value.map(|v| v.to_string()),
            "market_value_currency": market_value_currency,
            "acquisition_price": self.acquisition_price.map(|p| p.to_string()),
            "acquisition_currency": self.acquisition_currency,
        });

        Some(SecurityHolding {
            isin: self.isin.map(Isin::new),
            wkn: self.wkn.map(Wkn::new),
            name,
            quantity,
            price: self.price,
            price_currency: self.price_currency.or_else(|| self.acquisition_currency.clone()).map(Currency::new),
            price_date: self.price_date,
            market_value,
            market_value_currency: market_value_currency.map(Currency::new),
            acquisition_value,
            profit_loss,
            exchange: self.exchange,
            depot_id: depot_id.map(str::to_string),
            raw,
        })
    }
}

/// Parse an MT535 statement (one or more messages) into holdings.
pub(crate) fn parse_mt535(data: &[u8]) -> Vec<SecurityHolding> {
    let (text, _, _) = encoding_rs::WINDOWS_1252.decode(data);
    // Some banks use "@@" as line separator inside FinTS binary data.
    let text = text.replace("@@", "\n");

    let mut holdings = Vec::new();
    let mut depot_id: Option<String> = None;
    let mut current: Option<Position> = None;

    for f in fields(&text) {
        match (f.tag, f.value.as_str()) {
            ("16R", "FIN") => current = Some(Position::default()),
            ("16S", "FIN") => {
                if let Some(h) = current.take().and_then(|p| p.into_holding(depot_id.as_deref())) {
                    holdings.push(h);
                }
            }
            ("97A", v) => {
                if let Some(("SAFE", account)) = qualified(v) {
                    // "BLZ/number" or just "number"
                    let number = account.rsplit('/').next().unwrap_or(account).trim();
                    depot_id = Some(number.to_string());
                }
            }
            _ => {
                if let Some(p) = current.as_mut() {
                    p.apply(&f);
                }
            }
        }
    }
    holdings
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATEMENT: &str = ":16R:GENL\r\n\
:28E:1/ONLY\r\n\
:20C::SEME//NONREF\r\n\
:23G:NEWM\r\n\
:98A::PREP//20260315\r\n\
:98A::STAT//20260315\r\n\
:22F::STTY//CUST\r\n\
:97A::SAFE//50010517/0123456789\r\n\
:17B::ACTI//Y\r\n\
:16S:GENL\r\n\
:16R:FIN\r\n\
:35B:ISIN DE0005140008\r\n\
/DE/514000\r\n\
DEUTSCHE BANK AG\r\n\
NAMENS-AKTIEN O.N.\r\n\
:90B::MRKT//ACTU/EUR42,5\r\n\
:94B::PRIC//LMAR/XETR\r\n\
:98A::PRIC//20260314\r\n\
:93B::AGGR//UNIT/100,\r\n\
:16R:SUBBAL\r\n\
:93C::TAVI//UNIT/AVAI/100,\r\n\
:16S:SUBBAL\r\n\
:19A::HOLD//EUR4250,\r\n\
:70E::HOLD//1STK++++20200101+\r\n\
238,5+EUR\r\n\
:16S:FIN\r\n\
:16R:FIN\r\n\
:35B:ISIN IE00B4L5Y983\r\n\
/DE/A0RPWH\r\n\
ISHSIII-CORE MSCI WORLD U.ETF\r\n\
:90B::MRKT//ACTU/EUR98,765\r\n\
:98C::PRIC//20260314173000\r\n\
:93B::AGGR//UNIT/16,8211\r\n\
:16S:FIN\r\n\
:16R:FIN\r\n\
:35B:ISIN DE0001102580\r\n\
BUNDESREP.DEUTSCHLAND ANL.V.2022\r\n\
:90A::MRKT//PRCT/101,25\r\n\
:93B::AGGR//FAMT/5000,\r\n\
:19A::HOLD//EUR5062,5\r\n\
:16S:FIN\r\n\
:16R:ADDINFO\r\n\
:19A::HOLP//EUR10000,\r\n\
:16S:ADDINFO\r\n\
-";

    #[test]
    fn parses_positions() {
        let h = parse_mt535(STATEMENT.as_bytes());
        assert_eq!(h.len(), 3);

        let db = &h[0];
        assert_eq!(db.isin.as_ref().unwrap().as_str(), "DE0005140008");
        assert_eq!(db.wkn.as_ref().unwrap().as_str(), "514000");
        assert_eq!(db.name, "DEUTSCHE BANK AG NAMENS-AKTIEN O.N.");
        assert_eq!(db.quantity, Decimal::from(100));
        assert_eq!(db.price, Some(Decimal::new(425, 1)));
        assert_eq!(db.price_currency.as_ref().unwrap().as_str(), "EUR");
        assert_eq!(db.price_date, NaiveDate::from_ymd_opt(2026, 3, 14));
        assert_eq!(db.exchange.as_deref(), Some("XETR"));
        assert_eq!(db.market_value, Some(Decimal::from(4250)));
        assert_eq!(db.acquisition_value, Some(Decimal::from(3850)));
        assert_eq!(db.profit_loss, Some(Decimal::from(400)));
        assert_eq!(db.depot_id.as_deref(), Some("0123456789"));
    }

    #[test]
    fn computes_value_when_19a_missing_and_reads_98c() {
        let etf = &parse_mt535(STATEMENT.as_bytes())[1];
        assert_eq!(etf.quantity, Decimal::from_str("16.8211").unwrap());
        assert_eq!(etf.price_date, NaiveDate::from_ymd_opt(2026, 3, 14));
        assert_eq!(etf.market_value, Some(Decimal::from_str("16.8211").unwrap() * Decimal::from_str("98.765").unwrap()));
        assert_eq!(etf.wkn.as_ref().unwrap().as_str(), "A0RPWH");
    }

    #[test]
    fn bonds_use_percent_of_face_amount() {
        let bond = &parse_mt535(STATEMENT.as_bytes())[2];
        assert_eq!(bond.isin.as_ref().unwrap().as_str(), "DE0001102580");
        assert!(bond.wkn.is_none());
        assert_eq!(bond.quantity, Decimal::from(5000));
        assert_eq!(bond.price, Some(Decimal::from_str("101.25").unwrap()));
        assert_eq!(bond.market_value, Some(Decimal::from_str("5062.5").unwrap()));
        assert_eq!(bond.raw["quantity_type"], "FAMT");
    }

    #[test]
    fn python_fints_style_sample() {
        // Lines from python-fints' MT535_Miniparser comments, with "@@" line breaks.
        let s = ":16R:FIN@@:35B:ISIN LU0635178014@@/DE/ETF127@@COMS.-MSCI EM.M.T.U.ETF I@@\
:90B::MRKT//ACTU/EUR38,82@@:98A::PRIC//20170428@@:93B::AGGR//UNIT/16,8211@@\
:19A::HOLD//EUR970,17@@:70E::HOLD//1STK@@23,968293+EUR@@:16S:FIN@@-";
        let h = parse_mt535(s.as_bytes());
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].name, "COMS.-MSCI EM.M.T.U.ETF I");
        assert_eq!(h[0].market_value, Some(Decimal::from_str("970.17").unwrap()));
        assert_eq!(h[0].raw["acquisition_price"], "3.968293");
    }

    #[test]
    fn negative_amounts_and_empty_depot() {
        assert_eq!(currency_amount("NEUR12,5"), Some(("EUR".into(), Decimal::from_str("-12.5").unwrap())));
        assert_eq!(amount("N3,"), Some(Decimal::from(-3)));
        let empty = ":16R:GENL\r\n:97A::SAFE//50010517/1\r\n:17B::ACTI//N\r\n:16S:GENL\r\n-";
        assert!(parse_mt535(empty.as_bytes()).is_empty());
    }

    #[test]
    fn garbage_does_not_panic() {
        for s in ["", ":", ":16R:FIN", ":16R:FIN\n:35B:\n:16S:FIN", ":19A::HOLD//€€€", ":90B::MRKT//ACTU/E", ":93B::AGGR//", "\u{fffd}:70E::HOLD//2"] {
            let _ = parse_mt535(s.as_bytes());
        }
    }
}
