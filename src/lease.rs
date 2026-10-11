use anyhow::{bail, Result};
use chrono::{DateTime, Duration, Utc};

pub const MAX_RENEWAL_SECONDS: u64 = 86_400;
pub const MAX_TTL_SECONDS: u64 = 31_536_000;

pub fn expires_after(seconds: u64) -> Result<DateTime<Utc>> {
    if seconds == 0 || seconds > MAX_TTL_SECONDS {
        bail!("TTL must be between 1 and {} seconds", MAX_TTL_SECONDS);
    }
    Ok(Utc::now() + Duration::seconds(seconds as i64))
}

pub fn renewed_expiry(current: Option<DateTime<Utc>>, seconds: u64) -> Result<DateTime<Utc>> {
    if seconds == 0 || seconds > MAX_RENEWAL_SECONDS {
        bail!(
            "Renewal TTL must be between 1 and {} seconds",
            MAX_RENEWAL_SECONDS
        );
    }
    let current = current
        .ok_or_else(|| anyhow::anyhow!("Permanent credentials do not have a renewable lease"))?;
    if current <= Utc::now() {
        bail!("Expired leases cannot be renewed");
    }
    let proposed = expires_after(seconds)?;
    if proposed < current {
        bail!("Renewal must not shorten the current lease");
    }
    Ok(proposed)
}
