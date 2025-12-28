use std::net::IpAddr;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "portify", author, version, about = "A high-performance network scanner", long_about = None)]
pub struct Args {
    /// Target IP address to scan
    pub target: String,

    /// Start port (default: 1)
    #[arg(default_value_t = 1)]
    pub start_port: u16,

    /// End port (default: 1000)
    #[arg(default_value_t = 1000)]
    pub end_port: u16,
}

pub struct ScanConfig {
    pub target_ip: IpAddr,
    pub start_port: u16,
    pub end_port: u16,
}

impl ScanConfig {
    pub fn parse() -> Result<Self, String> {
        let args = Args::parse();
        let target_ip: IpAddr = args.target.parse().map_err(|_| "Invalid IP address")?;

        if target_ip.is_ipv6() {
            return Err("IPv6 not supported".to_string());
        }

        if args.start_port > args.end_port {
            return Err("Start port cannot be greater than end port".to_string());
        }

        Ok(Self {
            target_ip,
            start_port: args.start_port,
            end_port: args.end_port,
        })
    }
}
