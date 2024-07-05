#![no_std]
#![no_main]
#![feature(macro_metavar_expr_concat)]

use core::time::Duration;

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
    EbpfContext,
};
use hawkeye_common::{Event, EventType};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map(name = "CALL_START")]
static mut CALL_START: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(32, 0); // event_type -> start_time

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::with_max_entries(256, 0);

macro_rules! uprobe_impl {
    ($fn_name:ident, $deadline:expr) => {
        #[uprobe]
        pub fn ${concat(userspace_fn_enter_, $fn_name)}(ctx: ProbeContext) -> u32 {
            userspace_fn_enter_impl(ctx, EventType::$fn_name).unwrap_or_else(|ret| ret as u32)
        }

        #[uretprobe]
        pub fn ${concat(userspace_fn_exit_, $fn_name)}(ctx: ProbeContext) -> u32 {
            userspace_fn_exit_impl(ctx, EventType::$fn_name, $deadline)
                .unwrap_or_else(|ret| ret as u32)
        }
    };
}

uprobe_impl!(clock_gettime, Duration::from_secs(1));
uprobe_impl!(fsync, Duration::from_secs(1));
uprobe_impl!(fdatasync, Duration::from_secs(1));

fn userspace_fn_enter_impl(_ctx: ProbeContext, event_type: EventType) -> Result<u32, i64> {
    let event_type_id: u32 = event_type.into();
    unsafe {
        let start_time = bpf_ktime_get_ns();
        CALL_START.insert(&event_type_id, &start_time, 0)?;
    };
    Ok(0)
}

fn userspace_fn_exit_impl(
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
