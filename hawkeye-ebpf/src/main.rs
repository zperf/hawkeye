#![no_std]
#![no_main]
#![feature(macro_metavar_expr_concat)]
#![allow(nonstandard_style)]

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{kprobe, kretprobe, map, uprobe, uretprobe},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use core::time::Duration;
use hawkeye_common::{Event, EventType, ToStr};

static DEFAULT_DEADLINE: Duration = Duration::from_secs(1);

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::with_max_entries(1024, 0);

macro_rules! ufn_impl {
    ($name:ident, $deadline:expr) => {
        // pid -> start_time
        #[map]
        static mut ${concat(call_start_, $name)}: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(32, 0);

        #[uprobe]
        pub fn ${concat(ufn_enter_, $name)}(ctx: ProbeContext) -> u32 {
            unsafe {
                probe_enter_impl(ctx, EventType::$name, &mut ${concat(call_start_, $name)}).unwrap_or_else(|ret| ret as u32)
            }
        }

        #[uretprobe]
        pub fn ${concat(ufn_exit_, $name)}(ctx: ProbeContext) -> u32 {
            unsafe {
                probe_exit_impl(ctx, EventType::$name, $deadline, &mut ${concat(call_start_, $name)})
                    .unwrap_or_else(|ret| ret as u32)
            }
        }
    };
}

// ufn: userspace fn probe
ufn_impl!(clock_gettime, DEFAULT_DEADLINE);
ufn_impl!(fsync, DEFAULT_DEADLINE);
ufn_impl!(fdatasync, DEFAULT_DEADLINE);
ufn_impl!(posix_fadvise, DEFAULT_DEADLINE);

macro_rules! kfn_impl {
    ($name:ident, $deadline:expr) => {
        #[map]
        static mut ${concat(call_start_, $name)}: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(32, 0);

        #[kprobe]
        pub fn ${concat(kfn_enter_, $name)}(ctx: ProbeContext) -> u32 {
            unsafe {
                probe_enter_impl(ctx, EventType::$name, &mut ${concat(call_start_, $name)}).unwrap_or_else(|ret| ret as u32)
            }
        }

        #[kretprobe]
        pub fn ${concat(kfn_exit_, $name)}(ctx: ProbeContext) -> u32 {
            unsafe {
                probe_exit_impl(ctx, EventType::$name, $deadline, &mut ${concat(call_start_, $name)})
                    .unwrap_or_else(|ret| ret as u32)
            }
        }
    }
}

// kfn: kernel space fn probe
kfn_impl!(down_killable, DEFAULT_DEADLINE);
kfn_impl!(down_read_killable, DEFAULT_DEADLINE);
kfn_impl!(down_write_killable, DEFAULT_DEADLINE);

fn probe_enter_impl(
    ctx: ProbeContext,
    _event_type: EventType,
    m: &mut HashMap<u32, u64>,
) -> Result<u32, i64> {
    let pid = ctx.pid();
    // let event_type_id: u32 = event_type.into();
    unsafe {
        let start_time = bpf_ktime_get_ns();
        m.insert(&pid, &start_time, 0)?;
    };
    Ok(0)
}

fn probe_exit_impl(
    ctx: ProbeContext,
    event_type: EventType,
    deadline: Duration,
    m: &mut HashMap<u32, u64>,
) -> Result<u32, i64> {
    let pid = ctx.pid();

    unsafe {
        if let Some(start) = m.get(&pid) {
            let elapsed_ns = bpf_ktime_get_ns() - start;
            m.remove(&pid)?;
            info!(
                &ctx,
                "event: {}, pid: {}, call elapsed {}ns",
                event_type.to_str(),
                pid,
                elapsed_ns
            );
            if elapsed_ns > deadline.as_nanos() as u64 {
                let event = Event {
                    pid,
                    elapsed_ns,
                    event_type,
                };
                EVENTS.output(&ctx, &event, 0);
            }
        }
    };

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
