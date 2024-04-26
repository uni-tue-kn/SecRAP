use aya_ebpf::bindings::TC_ACT_OK;
use aya_ebpf::helpers::{bpf_skb_change_head, bpf_skb_change_tail};
use aya_ebpf::memcpy;
use aya_log_ebpf::{debug, error, info, warn};
use ebpf_helper::{compute_hash, ContextWrapper, ptr_at, ptr_mut_at, STEP_SIZE, TX_SEQ};
use crate::{ECP_HEADER_OFFSET, ETHERTYPE_ECP, INTEGRITY_SIGNATURE_POSITION};

fn increase_header_tc(ctx: &ContextWrapper) -> Result<(), ()> {
    let ret = unsafe { bpf_skb_change_head(ctx.inner_skb().skb, 32 + 2 + 8, 0) };

    if ret != 0 {
        error!(ctx, "Adjust head error. Aborting.");
        return Err(());
    }

    debug!(ctx, "Adjust header was successful. New size {}", ctx.data_end() - ctx.data());
    Ok(())
}

fn write_signature(ctx: &ContextWrapper, signature: &mut [u8], offset: usize) -> Result<(), ()> {
    if offset + 32 <= (ctx.data_end() - ctx.data()) {
        let hash_position: *mut [u8; 32] = ptr_mut_at(&ctx, offset)?;

        unsafe {
            memcpy(hash_position.as_mut_ptr(), signature.as_mut_ptr(), 32);
        }
    }

    Ok(())
}

fn rewrite_ecp_subtype(ctx: &ContextWrapper, offset: usize) -> Result<(), ()> {
    let ecp_header: *mut u16 = ptr_mut_at(&ctx, offset)?;
    let ecp_dtls_header: *mut u16 = ptr_mut_at(&ctx, offset + 4 + 32)?;

    unsafe {

        // set original subtype in etls header
        let subtype = (*ecp_header).to_be() as u16 & 0b0000001111111111;

        *ecp_dtls_header = subtype.to_be();

        // remove original subtype
        *ecp_header = (*ecp_header) & 0b0000000011111100;
        // add subtype 0x4
        *ecp_header = (*ecp_header) | 0b0000010000000000;

    }

    Ok(())
}

pub fn tc_hook(ctx: ContextWrapper) -> Result<i32, ()> {
    let sign = true;
    let eth_type: *const u16 = ptr_at(&ctx, 12)?;

    // We sign only ECP packets
    if  unsafe { *eth_type } == ETHERTYPE_ECP.to_be() {
        if !sign {
            warn!(&ctx, "ETLS disabled.");
            return Ok(TC_ACT_OK);
        }

        info!(&ctx, "Send ECP packet. Signing ...");

        let orig_len = ctx.data_end() - ctx.data();

        // Align payload temporarily to 64 byte for sha computation
        // We need this to apply our sha256 on 64 byte blocks for efficiency reasons
        {
            // 8 byte sequence number of ETLS should be part of "signature payload"
            let payload_len = orig_len - (ECP_HEADER_OFFSET + 4) + 8;

            // we add an 8 byte (= 64 bit) sequence number
            let new_len = match payload_len % STEP_SIZE {
                0 => orig_len,
                d => orig_len + (STEP_SIZE - d)
            };

            //info!(&ctx, "Adjusting with {}", new_len - orig_len);
            let ret = unsafe { bpf_skb_change_tail(ctx.inner_skb().skb, new_len as u32, 0) };

            if ret != 0 {
                error!(&ctx, "Adjust tail error. Aborting");
                return Err(());
            }
        }

        // Add ETLS header
        increase_header_tc(&ctx)?;

        { // copy ethernet + ECP header at front again
            // old eth header
            let ethhdr: *mut [u8; 32 + 2 + 8] = ptr_mut_at(&ctx, 32 + 2 + 8)?;
            let new_ethhdr: *mut [u8; 32 + 2 + 8] = ptr_mut_at(&ctx, 0)?;

            unsafe {
                memcpy(new_ethhdr.as_mut_ptr(), ethhdr.as_mut_ptr(), 32 + 2 + 8);
            }
        }

        // get and set ETLS sequence number
        let seq = unsafe {
            let s = TX_SEQ.get(&0).unwrap_or(&0u64);
            TX_SEQ.insert(&0, &(s + 1), 0).expect("Error in tx seq update.");

            s
        };

        // write sequence number to packet
        {
            let seq_position: *mut [u8; 8] = ptr_mut_at(&ctx, ECP_HEADER_OFFSET + 4 + 32 + 2)?;
            let mut seq: [u8; 8] = u64::to_be_bytes(*seq);
            unsafe {
                memcpy(seq_position.as_mut_ptr(), seq.as_mut_ptr(), 8);
            }
        }

        let mut signature = compute_hash(&ctx, ECP_HEADER_OFFSET + 4 + 32 + 2, 0)?;

        // Remove temporary 64 byte alignment = original packet without padding
        {
            let ret = unsafe { bpf_skb_change_tail(ctx.inner_skb().skb, (orig_len + 32 + 2 + 8) as u32, 0) };


            if ret != 0 {
                error!(&ctx, "Adjust tail error. Aborting");
                return Err(());
            }
        }


        debug!(&ctx, "Write signature.");
        write_signature(&ctx, &mut signature, INTEGRITY_SIGNATURE_POSITION)?;

        debug!(&ctx, "Rewrite subtype");
        rewrite_ecp_subtype(&ctx, 14)?;
    }
    else {
        info!(&ctx, "Send non-ECP packet.");
    }

    Ok(TC_ACT_OK)
}
