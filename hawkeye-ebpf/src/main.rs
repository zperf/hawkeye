#![no_std]
#![no_main]

use core::time::Duration;

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use hawkeye_common::Event;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static mut CALL_START: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(4, 0);

#[map]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::with_max_entries(1024, 0);

#[uprobe]
pub fn on_libc_fn_enter(ctx: ProbeContext) -> u32 {
    match enter_fn(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn enter_fn(ctx: ProbeContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    unsafe {
        let start_time = bpf_ktime_get_ns();
        CALL_START.insert(&pid, &start_time, 0)?;
    };
    Ok(0)
}

#[uretprobe]
pub fn on_libc_fn_exit(ctx: ProbeContext) -> u32 {
    match exit_fn(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn exit_fn(ctx: ProbeContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    unsafe {
        if let Some(start) = CALL_START.get(&pid) {
            let elapsed = bpf_ktime_get_ns() - start;
            CALL_START.remove(&pid)?;
            info!(&ctx, "pid: {}, call elapsed {}ns", pid, elapsed);

            // trigger alert
            if elapsed > Duration::from_nanos(100).as_nanos() as u64 {
                info!(&ctx, "alert!");
                let event = Event {
                    pid,
                    elapsed_ns: elapsed,
                };
                EVENTS.output(&ctx, &event, 0);
            }
        }
    };
    Ok(0)
}
