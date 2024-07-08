#![no_std]
#![no_main]
#![feature(macro_metavar_expr_concat)]

use core::time::Duration;

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, uprobe, uretprobe, kprobe, kretprobe},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
    EbpfContext,
};
use hawkeye_common::{Event, EventType};

static DEFAULT_DEADLINE: Duration = Duration::from_secs(1);

#[map(name = "CALL_START")]
static mut CALL_START: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(32, 0); // event_type -> start_time

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::with_max_entries(1024, 0);

// TODO: add more probes

macro_rules! ufn_impl {
    ($name:ident, $deadline:expr) => {
        #[uprobe]
        pub fn ${concat(ufn_enter_, $name)}(ctx: ProbeContext) -> u32 {
            probe_enter_impl(ctx, EventType::$name).unwrap_or_else(|ret| ret as u32)
        }

        #[uretprobe]
        pub fn ${concat(ufn_exit_, $name)}(ctx: ProbeContext) -> u32 {
            probe_exit_impl(ctx, EventType::$name, $deadline)
                .unwrap_or_else(|ret| ret as u32)
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
        #[kprobe]
        pub fn ${concat(kfn_enter_, $name)}(ctx: ProbeContext) -> u32 {
            probe_enter_impl(ctx, EventType::$name).unwrap_or_else(|ret| ret as u32)
        }

        #[kretprobe]
        pub fn ${concat(kfn_exit_, $name)}(ctx: ProbeContext) -> u32 {
            probe_exit_impl(ctx, EventType::$name, $deadline)
                .unwrap_or_else(|ret| ret as u32)
        }
    }
}

// kfn: kernel space fn probe
kfn_impl!(down_killable, DEFAULT_DEADLINE);
kfn_impl!(down_read_killable, DEFAULT_DEADLINE);
kfn_impl!(down_write_killable, DEFAULT_DEADLINE);

fn probe_enter_impl(_ctx: ProbeContext, event_type: EventType) -> Result<u32, i64> {
    let event_type_id: u32 = event_type.into();
    unsafe {
        let start_time = bpf_ktime_get_ns();
        CALL_START.insert(&event_type_id, &start_time, 0)?;
    };
    Ok(0)
}

fn probe_exit_impl(
    ctx: ProbeContext,
    event_type: EventType,
    deadline: Duration,
) -> Result<u32, i64> {
    let pid = ctx.pid();

    unsafe {
        if let Some(start) = CALL_START.get(&pid) {
            let elapsed_ns = bpf_ktime_get_ns() - start;
            CALL_START.remove(&pid)?;
            // info!(&ctx, "pid: {}, call elapsed {}ns", pid, elapsed);
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
