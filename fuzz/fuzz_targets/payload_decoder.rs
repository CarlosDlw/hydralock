#![no_main]

use hydralock::format::payload::PayloadSection;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = PayloadSection::parse(data);
});
