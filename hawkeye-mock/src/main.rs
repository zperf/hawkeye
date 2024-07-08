use clap::Parser;
use clap::ValueEnum;
use log::info;
use nix::libc::CLOCK_MONOTONIC_RAW;
use nix::time::clock_gettime;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    mock_type: Vec<MockType>,

    #[arg(short, long, value_parser = parse_duration, default_value = "1")]
    interval: Duration,
}

fn parse_duration(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}

#[derive(Debug, ValueEnum, Clone)]
enum MockType {
    #[value(name = "clock_gettime")]
    ClockGetTime,

    #[value(name = "fsync")]
    FSync,

    #[value(name = "fdatasync")]
    FDataSync,
}

trait Ticker {
    fn tick(&mut self) -> Result<(), anyhow::Error>;
}

struct ClockTiker;

impl ClockTiker {
    fn new() -> Self {
        ClockTiker {}
    }
}

impl Ticker for ClockTiker {
    fn tick(&mut self) -> Result<(), anyhow::Error> {
        let _now = clock_gettime(CLOCK_MONOTONIC_RAW.into())?;
        Ok(())
    }
}

struct FlushTicker {
    file: tempfile::NamedTempFile,
    data_sync: bool,
}

impl FlushTicker {
    fn new(data_sync: bool) -> Result<Self, anyhow::Error> {
        let file = tempfile::NamedTempFile::new()?;
        info!("tmp file: {:?}", file.path().file_name().unwrap());
        Ok(FlushTicker { file, data_sync })
    }
}

impl Ticker for FlushTicker {
    fn tick(&mut self) -> Result<(), anyhow::Error> {
        writeln!(&self.file, "Brian was here. Briefly.")?;
        let fd = self.file.as_fd().as_raw_fd();
        unsafe {
            if self.data_sync {
                libc::fdatasync(fd);
            } else {
                libc::fsync(fd);
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let args = Args::parse();

    let mut tickers = Vec::new();
    for mock_type in args.mock_type.iter() {
        let ticker: Box<dyn Ticker> = match mock_type {
            MockType::ClockGetTime => Box::new(ClockTiker::new()),
            MockType::FDataSync => Box::new(FlushTicker::new(true)?),
            MockType::FSync => Box::new(FlushTicker::new(false)?),
        };
        tickers.push(ticker);
    }

    while !tickers.is_empty() {
        for ticker in tickers.iter_mut() {
            ticker.tick()?;
            thread::sleep(args.interval);
        }
    }

    Ok(())
}
