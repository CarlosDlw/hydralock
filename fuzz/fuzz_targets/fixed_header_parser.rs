#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= hydralock::format::header::FIXED_HEADER_LEN {
        let _ = hydralock::format::header::FixedHeader::parse(
            &data[..hydralock::format::header::FIXED_HEADER_LEN],
        );
    } else {
        let _ = hydralock::format::header::FixedHeader::parse(data);
    }
});
