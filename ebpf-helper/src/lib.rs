#![no_std]

use aya_ebpf::{programs::XdpContext, programs::TcContext, EbpfContext, bindings::xdp_md, macros::{map}, maps::HashMap};
use core::ffi::c_void;
use core::mem;
use aya_ebpf::programs::sk_buff::SkBuff;

// step size for sha256 hash of message
pub const STEP_SIZE: usize = 64;

// K XOR opad
// Provided by user space
#[map]
pub static KEY_OPAD: HashMap<u32, [u8; 64]> =
    HashMap::<u32, [u8; 64]>::with_max_entries(1024, 0);

// K XOR ipad
// Provided by user space
#[map]
pub static KEY_IPAD: HashMap<u32, [u8; 64]> =
    HashMap::<u32, [u8; 64]>::with_max_entries(1024, 0);

// Send sequence number
#[map]
pub static TX_SEQ: HashMap<u32, u64> =
    HashMap::<u32, u64>::with_max_entries(1024, 0);

// Receive sequence number
#[map]
pub static RX_SEQ: HashMap<u32, u64> =
    HashMap::<u32, u64>::with_max_entries(1024, 0);

pub enum ContextWrapper {
    XDP(XdpContext),
    TC(TcContext)
}

impl ContextWrapper {
    #[inline(always)]
    pub fn data(&self) -> usize {
        match &self {
            ContextWrapper::XDP(xdp) => xdp.data(),
            ContextWrapper::TC(tc) => tc.data()
        }
    }

    #[inline(always)]
    pub fn data_end(&self) -> usize {
        match &self {
            ContextWrapper::XDP(xdp) => xdp.data_end(),
            ContextWrapper::TC(tc) => tc.data_end()
        }
    }

    #[inline(always)]
    pub fn inner_xdp(&self) -> *mut xdp_md {
        match &self {
            ContextWrapper::XDP(xdp) => xdp.ctx,
            _ => panic!("Called inner_xdp on non XDP wrapper")
        }
    }

    #[inline(always)]
    pub fn inner_skb(&self) -> &SkBuff {
        match &self {
            ContextWrapper::TC(tc) => &tc.skb,
            _ => panic!("Called inner_skb on non TC wrapper")
        }
    }
}

impl EbpfContext for ContextWrapper {
    #[inline(always)]
    fn as_ptr(&self) -> *mut c_void {
        match &self {
            ContextWrapper::XDP(xdp) => xdp.ctx as *mut _,
            ContextWrapper::TC(tc) => tc.as_ptr()
        }
    }
}

#[inline(always)]
pub fn ptr_at<T>(ctx: &ContextWrapper, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_mut_at<T>(ctx: &ContextWrapper, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[inline(always)]
pub fn compute_hash(ctx: &ContextWrapper, offset: usize, index: u32) -> Result<[u8; 32], ()> {
    let second_part = {
        let mut hasher = sha256::Sha256::default();

        // K' XOR ipad
        let key_ipad = unsafe {
            KEY_IPAD.get(&index).unwrap_or(&[0u8; 64])
        };

        hasher.update(key_ipad);

        let len = ctx.data_end() - ctx.data();

        // concat with message
        for i in 0..20 {
            if offset + (i + 1) * STEP_SIZE > len {
                break;
            }

            let data: *const [u8; STEP_SIZE] = ptr_at(&ctx, offset + i * STEP_SIZE)?;
            let v = &unsafe { *data };
            hasher.update(v);
        }

        hasher.finish()
    };

    let mut hasher = sha256::Sha256::default();

    //K' XOR ipad
    let key_opad = unsafe {
        KEY_OPAD.get(&index).unwrap_or(&[0u8; 64])
    };

    hasher.update(key_opad);
    hasher.update(&second_part);

    let signature = hasher.finish();

    Ok(signature)
}