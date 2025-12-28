use std::process;

mod config;
mod scanner;
mod ui;

#[tokio::main]
async fn main() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Error: Root privileges required.");
        process::exit(1);
    }

    ui::print_banner();

    let config = match config::ScanConfig::parse() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    println!("Scanning {} (Ports {}-{})...", 
        config.target_ip, config.start_port, config.end_port);

    match scanner::run_scan(config.target_ip, config.start_port, config.end_port).await {
        Ok(mut ports) => ui::print_results(&mut ports),
        Err(e) => {
            eprintln!("Scan error: {}", e);
            process::exit(1);
        }
    }
}
