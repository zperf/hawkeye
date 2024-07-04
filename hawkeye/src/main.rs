use anyhow::anyhow;
use aya::maps::AsyncPerfEventArray;
use aya::programs::UProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use hawkeye_common::Event;
use log::{debug, error, info, warn};
use serde_json::json;
use tokio::{signal, task};

#[derive(Debug, Parser)]
struct Opt {
    #[arg(short, long)]
    pid: Option<i32>,

    #[arg(short, long, default_value = "clock_gettime")]
    fn_name: String,

    #[arg(
        short,
        long,
        default_value = include_str!("../../.webhook")
    )]
    webhook: String,

    #[arg(short, long)]
    cluster_id: String,
}

async fn send_alert(webhook: &String, message: String) -> Result<(), anyhow::Error> {
    let body = json!({
        "msgtype": "text",
        "text": {
            "content": message
        }
    });

    let client = reqwest::Client::new();
    client.post(webhook).json(&body).send().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/hawkeye"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/hawkeye"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut UProbe = bpf.program_mut("on_libc_fn_enter").unwrap().try_into()?;
    program.load()?;
    program.attach(Some(&opt.fn_name), 0, "libc", opt.pid)?;

    let program: &mut UProbe = bpf.program_mut("on_libc_fn_exit").unwrap().try_into()?;
    program.load()?;
    program.attach(Some(&opt.fn_name), 0, "libc", opt.pid)?;

    let event_map = bpf
        .take_map("EVENTS")
        .ok_or(anyhow!("Can't find event map in eBPF program"))?;
    let mut events = AsyncPerfEventArray::try_from(event_map)?;

    for cpu_id in aya::util::online_cpus()? {
        let mut buf = events.open(cpu_id, None)?;
        let fn_name = opt.fn_name.clone();
        let webhook = opt.webhook.clone();
        let cluster = opt.cluster_id.clone();

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| bytes::BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const Event;
                    let event = unsafe { ptr.read_unaligned() };
                    info!(
                        "new alert, pid: {}, elapsed_ns: {}",
                        event.pid, event.elapsed_ns
                    );
                    let message = format!(
                        "[ALERT] {} takes too loooooooong! cluster: {}, pid: {}, elapsed: {}ns",
                        fn_name, cluster, event.pid, event.elapsed_ns
                    );
                    if let Err(e) = send_alert(&webhook, message).await {
                        error!("Alert send failed, ex: {}", e);
                    }
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
