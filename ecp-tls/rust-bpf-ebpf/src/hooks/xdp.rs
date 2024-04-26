use aya_ebpf::helpers::*;
use aya_log_ebpf::{error, info, warn};
use aya_ebpf::bindings::xdp_action::{XDP_PASS};
use aya_ebpf::cty::c_int;
use aya_ebpf::memcpy;
use ebpf_helper::{compute_hash, ContextWrapper, ptr_at, STEP_SIZE, RX_SEQ, ptr_mut_at};
use crate::{ECP_HEADER_OFFSET, ECP_INTEGRITY_SUBTYPE, ETLS_HEADER_SIZE};

fn rewrite_ecp_subtype(ctx: &ContextWrapper, offset: usize) -> Result<(), ()> {
    let ecp_header: *mut u16 = ptr_mut_at(&ctx, offset)?;
    let ecp_dtls_header: *mut u16 = ptr_mut_at(&ctx, offset + 4 + 32)?;

    unsafe {

        // get original subtype in etls header
        let subtype = (*ecp_dtls_header).to_be() as u16 & 0b0000001111111111;

        // remove original subtype
        *ecp_header = (*ecp_header) & 0b0000000011111100;

        // add etls subtype
        *ecp_header = (*ecp_header) | subtype.to_be();

    }

    Ok(())
}

pub fn xdp_hook(ctx: ContextWrapper) -> Result<u32, ()> {
    let remove_etls = true;

    let len = ctx.data_end() - ctx.data();

    // ecp header
    let ecp_header_parts: *const u16 = ptr_at(&ctx, ECP_HEADER_OFFSET)?;

    let subtype = unsafe {
        (*ecp_header_parts).to_be() & 0b000000111111111
    };

    if subtype == ECP_INTEGRITY_SUBTYPE {
        // ethernet header + ecp header
        let payload_position = ECP_HEADER_OFFSET + 4 + 32 + 2;

        // Align payload to 64 byte
        let payload_len = len - payload_position;

        let delta = match payload_len % STEP_SIZE {
            0 => 0,
            d => STEP_SIZE - d
        };

        unsafe {
            //info!(&ctx, "Adjusting with {}", delta);
            let ret = bpf_xdp_adjust_tail(ctx.inner_xdp(), delta as c_int);

            if ret != 0 {
                error!(&ctx, "XDP adjust tail error. Aborting");
                return Err(());
            }
        }

        let signature: [u8; 32] = compute_hash(&ctx, payload_position, 0)?;

        unsafe {
            let ret = bpf_xdp_adjust_tail(ctx.inner_xdp(), -1 * delta as c_int);

            if ret != 0 {
                error!(&ctx, "XDP adjust tail error. Aborting");
                return Err(());
            }
        }

        for i in 0..32 {
            let packet_signature: *const u8 = ptr_at(&ctx, 14 + 4 + i)?;
            let val = unsafe { *packet_signature };
            let signature_val = signature[i];

            if val != signature_val {
                info!(&ctx, "{} vs {}", val, signature_val);
                warn!(&ctx, "HMAC invalid at byte {}. Dropping packet.", i+1);
                return Err(());
            }
        }

        let seq: *const u64 = ptr_at(&ctx, ECP_HEADER_OFFSET + 4 + 32 + 2)?;
        let seq = unsafe {*seq};
        let rx_seq = unsafe {
            RX_SEQ.get(&0).unwrap_or(&0)
        };

        if seq.to_be() < *rx_seq {
            warn!(&ctx, "Sequence number too small. Received: {}. Expected: {}. Dropping packet.", seq.to_be(), *rx_seq);
            return Err(());
        }


        RX_SEQ.insert(&0, &(seq.to_be() + 1), 0).expect("Error in update RX seq.");

        info!(&ctx, "Packet has correct HMAC!.");

        if remove_etls {
            info!(&ctx, "Removing ETLS header.");

            rewrite_ecp_subtype(&ctx, 14)?;

            { // copy ethernet + ECP header at new position
                // old eth header
                let ethhdr: *mut [u8; 14 + 4] = ptr_mut_at(&ctx, 0)?;
                let new_ethhdr: *mut [u8; ETLS_HEADER_SIZE] = ptr_mut_at(&ctx, ETLS_HEADER_SIZE)?;

                unsafe {
                    memcpy(new_ethhdr.as_mut_ptr(), ethhdr.as_mut_ptr(), 14 + 4);
                }

                let ret = unsafe {
                    bpf_xdp_adjust_head(ctx.inner_xdp(), ETLS_HEADER_SIZE as c_int)
                };

                if ret != 0 {
                    error!(&ctx, "Removing ETLS header failed. Dropping packet.");
                    return Err(());
                }
            }
        }

        Ok(XDP_PASS)
    }
    else {
        warn!(&ctx, "Received non signed ECP packet.");
        Ok(XDP_PASS)
    }

}