#![no_std]
#![no_main]

use aya_ebpf::{
    macros::uprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[uprobe]
pub fn hawkeye(ctx: ProbeContext) -> u32 {
    match try_hawkeye(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_hawkeye(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function clock_gettime called by libc");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
