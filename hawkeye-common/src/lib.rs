#![no_std]
#![allow(nonstandard_style)]

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub struct Event {
    pub pid: u32,
    pub elapsed_ns: u64,
    pub event_type: EventType,
}

#[derive(Copy, Clone)]
pub enum EventType {
    clock_gettime,
    fsync,
    fdatasync,
}

impl Into<u32> for EventType {
    fn into(self) -> u32 {
        match self {
            EventType::clock_gettime => 0,
            EventType::fsync => 1,
            EventType::fdatasync => 2,
        }
    }
}
