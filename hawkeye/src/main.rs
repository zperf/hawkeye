mod alert;
mod cli;

use std::vec;

use anyhow::anyhow;
use aya::maps::AsyncPerfEventArray;
use aya::programs::{KProbe, UProbe};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use hawkeye_common::Event;
use log::{debug, error, info, warn};
use tokio::{signal, task};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = cli::Opt::parse();
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

    if let Some(ufns) = &opt.ufns {
        if opt.attach_target.is_none() {
            return Err(anyhow!("Attach target is not defined"));
        }
        let attach_target = opt.attach_target.unwrap();

        for fn_name in ufns.iter() {
            for prefix in vec!["ufn_enter_", "ufn_exit_"] {
                let mut name = String::from(prefix);
                name.push_str(&fn_name.as_str());

                let program: &mut UProbe = bpf.program_mut(&name).unwrap().try_into()?;
                program.load()?;
                // TODO: check attach target
                program.attach(Some(fn_name), 0, &attach_target, opt.pid)?;
                info!("Attached to {} {}, loading program: {}", &attach_target, fn_name, &name);
            }
        }
    }

    if let Some(kfns) = &opt.kfns {
        for fn_name in kfns.iter() {
            for prefix in vec!["kfn_enter_", "kfn_exit_"] {
                let mut name = String::from(prefix);
                name.push_str(&fn_name.as_str());

                let program: &mut KProbe = bpf.program_mut(&name).unwrap().try_into()?;
                program.load()?;
                program.attach(fn_name, 0)?;
                info!("Attached to {}, loading program: {}", fn_name, &name);
            }
        }
    }

    let event_map = bpf
        .take_map("EVENTS")
        .ok_or(anyhow!("Can't find event map in eBPF program"))?;
    let mut events = AsyncPerfEventArray::try_from(event_map)?;

    for cpu_id in aya::util::online_cpus()? {
        for fn_name in opt
            .ufns
            .clone()
            .unwrap_or(vec![])
            .iter()
            .chain(opt.kfns.clone().unwrap_or(vec![]).iter())
        {
            let mut buf = events.open(cpu_id, None)?;
            let webhook = opt.webhook.clone();
            let hostname = opt.hostname.clone();
            let name = fn_name.clone();

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
                        let message = alert::get_message(&name, &hostname, &event);
                        if let Some(wh) = &webhook {
                            if !wh.trim().is_empty() {
                                if let Err(e) = alert::send(&wh, message).await {
                                    error!("Alert send failed, ex: {}", e);
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
