#![no_main]

use hydralock::format::metadata::MetadataSection;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = MetadataSection::parse(data);
});
