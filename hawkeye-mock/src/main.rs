use std::thread;
use std::time;
use std::time::Instant;

use log::info;
use nix::libc::CLOCK_MONOTONIC_RAW;
use nix::time::clock_gettime;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // env_logger::init();

    loop {
        // let start = Instant::now();
        let _now = clock_gettime(CLOCK_MONOTONIC_RAW.into())?;
        // let end = start.elapsed();
        // println!("clock_gettime elapsed: {}ns", end.as_nanos());
        thread::sleep(time::Duration::from_millis(1000));
    }
}
