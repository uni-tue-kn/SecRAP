use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Ebpf};
use aya::maps::HashMap;
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use sha256;

// Key exchange is out of scope for POC
const SUPER_SECRET_KEY: &[u8; 30] = b"Super secret key used for hmac";

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

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
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/rust-bpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/rust-bpf"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    info!("Setup hmac keys...");

    let mut padded_key = [0; 64];

    if SUPER_SECRET_KEY.len() < 64 {
        for (i, b) in padded_key.iter_mut().enumerate() {
            *b = *SUPER_SECRET_KEY.get(i).unwrap_or(&0);
        }
    }
    else {
        let mut hasher = sha256::Sha256::default();
        hasher.update(SUPER_SECRET_KEY);
        let key = hasher.finish();

        for (i, b) in padded_key.iter_mut().enumerate() {
            *b = *key.get(i).unwrap_or(&0);
        }
    }

    let mut opad_key = padded_key;
    let mut ipad_key = padded_key.clone();

    for b in opad_key.iter_mut() {
        *b ^= 0x5c;
    }

    for b in ipad_key.iter_mut() {
        *b ^= 0x36;
    }

    let mut key_opad_map: HashMap<_, u32, [u8; 64]> = HashMap::try_from(bpf.map_mut("KEY_OPAD").unwrap())?;
    key_opad_map.insert(0, opad_key, 0).expect("Key OPAD insert failed.");

    let mut key_ipad_map: HashMap<_, u32, [u8; 64]> = HashMap::try_from(bpf.map_mut("KEY_IPAD").unwrap())?;
    key_ipad_map.insert(0, ipad_key, 0).expect("Key IPAD insert failed.");

    // load XDP
    let program: &mut Xdp = bpf.program_mut("rust_bpf").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // load TC
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf.program_mut("ecp_tls_egress").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Egress)?;


    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
