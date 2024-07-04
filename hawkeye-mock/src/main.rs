use std::thread;
use std::time;

use nix::libc::CLOCK_MONOTONIC_RAW;
use nix::time::clock_gettime;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    loop {
        let _now = clock_gettime(CLOCK_MONOTONIC_RAW.into())?;
        thread::sleep(time::Duration::from_millis(1000));
    }
}
