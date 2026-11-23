//! RFC 3339 formatting without a clock or a date library. The host supplies
//! `now_ms`; the core only formats it.

/// Parse a UTC timestamp in the form Lurensic writes, `2026-11-17T09:30:00.000Z`
/// (fractional seconds optional), into milliseconds since the epoch.
pub fn parse_rfc3339(s: &str) -> Option<u64> {
    let s = s.trim().strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.splitn(3, '-').map(|p| p.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
    let mut t = hms.splitn(3, ':').map(|p| p.parse::<u64>().ok());
    let (hh, mm, ss) = (t.next()??, t.next()??, t.next()??);
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let millis = if frac.is_empty() {
        0
    } else {
        let digits: String = frac.chars().take(3).collect();
        if !digits.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        format!("{digits:0<3}").parse::<u64>().ok()?
    };
    let days = days_from_civil(y, m as u32, day as u32);
    if days < 0 {
        return None;
    }
    Some(((days as u64 * 86_400 + hh * 3600 + mm * 60 + ss) * 1000) + millis)
}

/// Howard Hinnant's civil-to-days algorithm.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = (y - era * 400) as u64;
    let mp = u64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + u64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

pub fn rfc3339(ms: u64) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(951_782_400_123), "2000-02-29T00:00:00.123Z");
        assert_eq!(rfc3339(1_794_700_800_000), "2026-11-15T00:00:00.000Z");
    }

    #[test]
    fn parses_what_it_formats() {
        for ms in [0, 951_782_400_123, 1_794_700_800_000, 1_794_787_199_999] {
            assert_eq!(parse_rfc3339(&rfc3339(ms)), Some(ms));
        }
        assert_eq!(
            parse_rfc3339("2026-11-15T00:00:00Z"),
            Some(1_794_700_800_000)
        );
        assert_eq!(
            parse_rfc3339("2026-11-15T00:00:00.5Z"),
            Some(1_794_700_800_500)
        );
        for bad in [
            "",
            "2026-11-15",
            "2026-13-01T00:00:00Z",
            "2026-11-15T00:00:00+01:00",
            "x",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }
}
