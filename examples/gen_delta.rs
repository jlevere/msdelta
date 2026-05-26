use std::fs;

fn main() {
    let base = fs::read("tests/fixtures/base_manifest.bin").unwrap();
    let fixture = fs::read("tests/fixtures/amd64_microsoft-windows-core_31bf3856ad364e35_10.0.26100.1_none_a943f5e781a44c5c.manifest").unwrap();
    let target = msdelta::pa30::apply(&base, &fixture[4..]).unwrap();
    let delta = msdelta::pa30::create(&base, &target).unwrap();
    fs::write("/tmp/custom_huffman.pa30", &delta).unwrap();
    println!("Custom Huffman delta: {} bytes (target: {} bytes)", delta.len(), target.len());
}
