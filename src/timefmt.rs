use chrono::{DateTime, SecondsFormat, Utc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn format_system_time(value: SystemTime) -> String {
    DateTime::<Utc>::from(value).to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn format_from_elapsed(elapsed: Duration) -> String {
    let ts = SystemTime::now().checked_sub(elapsed).unwrap_or(UNIX_EPOCH);
    format_system_time(ts)
}
