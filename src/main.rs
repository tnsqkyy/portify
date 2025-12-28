use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet::transport::{self, TransportChannelType, TransportProtocol};
use std::io::{self, Write};
use std::net::IpAddr;
use std::process;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const PACKET_SIZE: usize = 20;

fn main() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Error: Root privileges required (sudo).");
        process::exit(1);
    }

    print_banner();

    let target_ip: IpAddr = loop {
        let input = get_input("Target IP: ");
        match IpAddr::from_str(&input) {
            Ok(addr) => {
                if addr.is_ipv6() {
                    println!("Error: Raw IPv6 scanning is not supported.");
                } else {
                    break addr;
                }
            }
            Err(_) => println!("Error: Invalid IP address."),
        }
    };

    let start_port: u16 = loop {
        let input = get_input("Start Port: ");
        match input.parse() {
            Ok(p) => break p,
            Err(_) => println!("Error: Invalid port."),
        }
    };

    let end_port: u16 = loop {
        let input = get_input("End Port: ");
        match input.parse() {
            Ok(p) => {
                if p >= start_port {
                    break p;
                } else {
                    println!("Error: End Port must be >= Start Port.");
                }
            }
            Err(_) => println!("Error: Invalid port."),
        }
    };

    let (interface, source_ip) = match get_default_interface() {
        Some(res) => res,
        None => {
            eprintln!("Error: No valid IPv4 interface found.");
            process::exit(1);
        }
    };

    println!("\nInterface: {} ({})", style(&interface.name).cyan(), source_ip);
    println!("Scanning {}...", style(target_ip).yellow());

    let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut tx, mut rx) = transport::transport_channel(4096, protocol).expect("Socket error");

    let is_scanning = Arc::new(AtomicBool::new(true));
    let scan_flag = is_scanning.clone();
    
    let open_ports = Arc::new(Mutex::new(Vec::new()));
    let results_clone = open_ports.clone();

    thread::spawn(move || {
        let mut iter = transport::tcp_packet_iter(&mut rx);
        while scan_flag.load(Ordering::Relaxed) {
            if let Ok((packet, addr)) = iter.next() {
                if addr == target_ip {
                    let flags = packet.get_flags();
                    if (flags & TcpFlags::SYN) != 0 && (flags & TcpFlags::ACK) != 0 {
                        let mut ports = results_clone.lock().unwrap();
                        if !ports.contains(&packet.get_source()) {
                            ports.push(packet.get_source());
                        }
                    }
                }
            }
        }
    });

    let count = (end_port - start_port + 1) as u64;
    let pb = ProgressBar::new(count);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    let mut packet_buffer = [0u8; PACKET_SIZE];
    
    for port in start_port..=end_port {
        let mut tcp_packet = MutableTcpPacket::new(&mut packet_buffer).unwrap();
        
        tcp_packet.set_source(54321);
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(0);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(64240);
        tcp_packet.set_data_offset(5);
        
        let checksum = tcp::ipv4_checksum(
            &tcp_packet.to_immutable(), 
            &source_ip, 
            &target_ip.match_ipv4()
        );
        tcp_packet.set_checksum(checksum);

        let _ = tx.send_to(tcp_packet, target_ip);
        pb.inc(1);
    }

    pb.finish_with_message("Done");
    
    thread::sleep(Duration::from_secs(2));
    is_scanning.store(false, Ordering::Relaxed);
    
    let mut ports = open_ports.lock().unwrap();
    ports.sort();

    println!("\n{:<10} {:<25} {}", "PORT", "SERVICE", "STATUS");
    println!("{:<10} {:<25} {}", "----", "-------", "------");

    if ports.is_empty() {
        println!("No open ports found.");
    } else {
        for port in ports.iter() {
            println!("{:<10} {:<25} {}", 
                style(port).bold(), 
                get_service_name(*port),
                style("OPEN").green()
            );
        }
    }
    println!("\nScan complete.");
}

fn get_input(prompt: &str) -> String {
    print!("{}", style(prompt).bold());
    io::stdout().flush().unwrap();
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).expect("Error");
    buffer.trim().to_string()
}

fn get_default_interface() -> Option<(NetworkInterface, std::net::Ipv4Addr)> {
    let interfaces = datalink::interfaces();
    for iface in interfaces {
        if !iface.is_loopback() && iface.is_up() && !iface.ips.is_empty() {
            for ip in &iface.ips {
                if let IpAddr::V4(ipv4) = ip.ip() {
                    return Some((iface, ipv4));
                }
            }
        }
    }
    None
}

fn print_banner() {
    println!("{}", style("========================================").cyan());
    println!("{}", style("      PORTIFY: RAW SYN SCANNER v3.0     ").bold().cyan());
    println!("{}", style("========================================").cyan());
}

fn get_service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        631 => "IPP (CUPS)",
        3306 => "MySQL",
        3389 => "RDP",
        5037 => "ADB",
        5432 => "PostgreSQL",
        6379 => "Redis",
        8080 => "HTTP-Proxy",
        27017 => "MongoDB",
        _ => "Unknown",
    }
}

trait IpV4Match {
    fn match_ipv4(&self) -> std::net::Ipv4Addr;
}

impl IpV4Match for IpAddr {
    fn match_ipv4(&self) -> std::net::Ipv4Addr {
        match self {
            IpAddr::V4(ip) => *ip,
            _ => panic!("IPv6 error"),
        }
    }
}
