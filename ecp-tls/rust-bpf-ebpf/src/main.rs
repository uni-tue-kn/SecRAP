#![feature(exclusive_range_pattern)]
#![feature(array_ptr_get)]
#![no_std]
#![no_main]

mod hooks;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_ebpf::bindings::{TC_ACT_SHOT};
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
use ebpf_helper::{ContextWrapper};
use crate::hooks::tc::tc_hook;
use crate::hooks::xdp::xdp_hook;

// ECP header after Ethernet (14 bytes)
const ECP_HEADER_OFFSET: usize = 14;

const ETLS_HEADER_SIZE: usize = 32 + 2 + 8;
// ECP subtype for INTEGRITY
const ECP_INTEGRITY_SUBTYPE: u16 = 4;
// Ethertype ECP
const ETHERTYPE_ECP: u16 = 0x8940;
const INTEGRITY_SIGNATURE_POSITION: usize = 14 + 4;

#[xdp]
pub fn rust_bpf(ctx: XdpContext) -> u32 {
    let ctx = ContextWrapper::XDP(ctx);

    match xdp_hook(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}


#[classifier]
pub fn ecp_tls_egress(ctx: TcContext) -> i32 {
    let ctx = ContextWrapper::TC(ctx);

    tc_hook(ctx).unwrap_or_else(|_| TC_ACT_SHOT)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
