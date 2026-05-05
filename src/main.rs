fn main() {
    if let Err(e) = hydralock::cli::run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
