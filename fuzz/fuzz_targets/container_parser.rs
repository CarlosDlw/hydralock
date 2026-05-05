#![no_main]

use hydralock::format::footer::FooterSection;
use hydralock::format::header::{FIXED_HEADER_LEN, FixedHeader};
use hydralock::format::policy::PolicySection;
use hydralock::format::wraps::WrapsSection;
use hydralock::ops::decrypt::scan_payload_end;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < FIXED_HEADER_LEN {
        return;
    }

    let header = match FixedHeader::parse(&data[..FIXED_HEADER_LEN]) {
        Ok(h) => h,
        Err(_) => return,
    };

    let policy_start = FIXED_HEADER_LEN;
    let policy_end = match policy_start.checked_add(header.policy_len as usize) {
        Some(v) => v,
        None => return,
    };
    let wraps_start = policy_end;
    let wraps_end = match wraps_start.checked_add(header.wraps_len as usize) {
        Some(v) => v,
        None => return,
    };
    let metadata_start = wraps_end;
    let metadata_end = match metadata_start.checked_add(header.metadata_len as usize) {
        Some(v) => v,
        None => return,
    };
    let payload_start = header.payload_offset as usize;

    if data.len() < metadata_end || data.len() < payload_start {
        return;
    }

    let _ = PolicySection::parse(&data[policy_start..policy_end]);
    let _ = WrapsSection::parse(&data[wraps_start..wraps_end]);

    let payload_end = match scan_payload_end(data, payload_start) {
        Ok(v) => v,
        Err(_) => return,
    };

    if payload_end > data.len() {
        return;
    }

    let footer_bytes = &data[payload_end..];
    let _ = FooterSection::parse(footer_bytes);
});
