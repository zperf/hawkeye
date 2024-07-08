#![no_std]
#![allow(nonstandard_style)]

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub struct Event {
    pub pid: u32,
    pub elapsed_ns: u64,
    pub event_type: EventType,
}

// check the probe with bpftrace
#[derive(Copy, Clone)]
#[repr(u32)]
pub enum EventType {
    clock_gettime = 0,       // uprobe:/usr/lib/libc.so.6:clock_gettime
    fsync = 1,               // uprobe:/usr/lib/libc.so.6:fsync
    fdatasync = 2,           // uprobe:/usr/lib/libc.so.6:fdatasync
    down_killable = 3,       // kprobe:down_killable
    down_read_killable = 4,  // kprobe:down_read_killable
    down_write_killable = 5, // kprobe:down_write_killable
    posix_fadvise = 6,       // uprobe:/usr/lib/libc.so.6:posix_madvise
}

impl From<EventType> for u32 {
    fn from(value: EventType) -> Self {
        value as u32
    }
}
