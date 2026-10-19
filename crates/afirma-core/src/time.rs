//! Civil dates and times, and their XML Schema (`xsd:dateTime`) form.

/// Civil date and time in a given UTC offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DateTime {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    /// Day of the week, 0 = Monday.
    pub weekday: u32,
    /// Offset from UTC in minutes.
    pub offset_minutes: i32,
}

impl DateTime {
    /// Converts a Unix time to the civil time at `offset_minutes` from UTC.
    pub fn from_unix(unix_seconds: i64, offset_minutes: i32) -> Self {
        let local = unix_seconds + i64::from(offset_minutes) * 60;
        let days = local.div_euclid(86_400);
        let secs = local.rem_euclid(86_400);
        // Howard Hinnant's civil_from_days.
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let year = yoe + era * 400 + i64::from(month <= 2);
        DateTime {
            year,
            month,
            day,
            hour: (secs / 3600) as u32,
            minute: (secs % 3600 / 60) as u32,
            second: (secs % 60) as u32,
            // 1970-01-01 was a Thursday.
            weekday: (days + 3).rem_euclid(7) as u32,
            offset_minutes,
        }
    }

    /// `xsd:dateTime` with the UTC offset (`2026-10-19T18:56:23+02:00`), as
    /// AutoFirma writes the XAdES `SigningTime`.
    pub fn to_xml(self) -> String {
        let sign = if self.offset_minutes < 0 { '-' } else { '+' };
        let offset = self.offset_minutes.unsigned_abs();
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{sign}{:02}:{:02}",
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            offset / 60,
            offset % 60
        )
    }
}

/// Days from 1970-01-01 to a civil date.
pub(crate) fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parses an `xsd:dateTime` (`2026-10-19T18:56:23.123+02:00`, `...Z`, or
/// without zone, taken as UTC) into a Unix time. Fractions of a second are dropped.
pub(crate) fn parse_xml_date_time(text: &str) -> Option<i64> {
    let text = text.trim();
    let (date, time) = text.split_once('T')?;
    let mut date_parts = date.splitn(3, '-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;

    let (clock, offset_minutes) = match time.find(['Z', '+', '-']) {
        Some(i) if &time[i..] == "Z" => (&time[..i], 0),
        Some(i) => {
            let (hours, minutes) = time[i + 1..].split_once(':')?;
            let minutes = hours.parse::<i64>().ok()? * 60 + minutes.parse::<i64>().ok()?;
            (
                &time[..i],
                if &time[i..=i] == "-" {
                    -minutes
                } else {
                    minutes
                },
            )
        }
        None => (time, 0),
    };
    let mut clock_parts = clock.splitn(3, ':');
    let hour: i64 = clock_parts.next()?.parse().ok()?;
    let minute: i64 = clock_parts.next()?.parse().ok()?;
    let second: i64 = clock_parts.next()?.split('.').next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 24 || minute > 59 {
        return None;
    }
    Some(
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
            - offset_minutes * 60,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_date_times() {
        // 2026-10-19T16:56:23Z
        let unix = 1_792_428_983;
        assert_eq!(
            DateTime::from_unix(unix, 120).to_xml(),
            "2026-10-19T18:56:23+02:00"
        );
        assert_eq!(
            DateTime::from_unix(unix, -150).to_xml(),
            "2026-10-19T14:26:23-02:30"
        );
        assert_eq!(parse_xml_date_time("2026-10-19T18:56:23+02:00"), Some(unix));
        assert_eq!(parse_xml_date_time("2026-10-19T14:26:23-02:30"), Some(unix));
        assert_eq!(parse_xml_date_time("2026-10-19T16:56:23.457Z"), Some(unix));
        assert_eq!(parse_xml_date_time("2026-10-19T16:56:23"), Some(unix));
        assert_eq!(parse_xml_date_time("2026-13-19T16:56:23"), None);
        assert_eq!(parse_xml_date_time("ayer"), None);
    }
}
