//! One suspend-aware clock. No wall-clock adjustments can change a boot's deadlines.
use nix::time::{ClockId, clock_gettime};
use std::time::{SystemTime, UNIX_EPOCH};
pub struct Clock {
    origin: u64,
    wall: u64,
}
fn continuous() -> u64 {
    #[cfg(target_os = "macos")]
    let id = ClockId::CLOCK_MONOTONIC; // Darwin CLOCK_MONOTONIC includes sleep (CLOCK_UPTIME_RAW does not).
    #[cfg(not(target_os = "macos"))]
    let id = ClockId::CLOCK_BOOTTIME;
    let t = clock_gettime(id).expect("suspend-aware clock unavailable");
    t.tv_sec() as u64 * 1000 + t.tv_nsec() as u64 / 1_000_000
}
impl Default for Clock {
    fn default() -> Self {
        Self {
            origin: continuous(),
            wall: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("wall clock before epoch")
                .as_millis() as u64,
        }
    }
}
impl Clock {
    pub fn now(&self) -> u64 {
        self.wall + continuous().saturating_sub(self.origin)
    }
}
