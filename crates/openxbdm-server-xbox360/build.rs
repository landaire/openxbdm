fn main() {
    // build_xbox360.sh passes the script through RUSTFLAGS, which cargo does
    // not track.
    println!("cargo:rerun-if-changed=link.x");
}
