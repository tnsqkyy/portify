use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet::transport::{self, TransportChannelType, TransportProtocol};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::Duration;
use rand::Rng;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::task;

const PACKET_SIZE: usize = 20;
const TARGET_PPS: u64 = 3000;

pub async fn run_scan(target_ip: IpAddr, start: u16, end: u16) -> Result<Vec<u16>, String> {
    let (interface, source_ip) = get_default_interface()
        .ok_or("No valid IPv4 interface found.")?;

    println!("Interface: {} ({})", interface.name, source_ip);

    let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut tx, mut rx) = transport::transport_channel(4096, protocol)
        .map_err(|e| format!("Socket error: {}", e))?;
    
    let mut rng = rand::thread_rng();
    let source_port: u16 = rng.gen_range(10000..60000);

    let is_scanning = Arc::new(AtomicBool::new(true));
    let scan_flag = is_scanning.clone();
    let found_ports = Arc::new(Mutex::new(Vec::new()));
    let ports_clone = found_ports.clone();

    let _rx_task = task::spawn_blocking(move || {
        let mut iter = transport::tcp_packet_iter(&mut rx);
        while scan_flag.load(Ordering::Relaxed) {
            if let Ok((packet, addr)) = iter.next() {
                // Logic lọc gói tin: Đúng IP đích và đúng Port nguồn mình đã random
                if addr == target_ip && packet.get_destination() == source_port {
                    let flags = packet.get_flags();
                    if (flags & TcpFlags::SYN) != 0 && (flags & TcpFlags::ACK) != 0 {
                        let mut ports = ports_clone.lock().unwrap();
                        if !ports.contains(&packet.get_source()) {
                            ports.push(packet.get_source());
                        }
                    }
                }
            }
        }
    });

    let total = (end - start + 1) as u64;
    let pb = ProgressBar::new(total);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    let mut packet_buffer = [0u8; PACKET_SIZE];

    let tx_task = task::spawn_blocking(move || {
        let packet_delay = Duration::from_micros(1_000_000 / TARGET_PPS);
        for dest_port in start..=end {
            let mut tcp_packet = MutableTcpPacket::new(&mut packet_buffer).unwrap();
            
            tcp_packet.set_source(source_port);
            tcp_packet.set_destination(dest_port);
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
            std::thread::sleep(packet_delay);
        }
        pb.finish_with_message("Done");
    });

    let _ = tx_task.await;

    tokio::time::sleep(Duration::from_millis(2000)).await;
    
    is_scanning.store(false, Ordering::Relaxed);

    let result = found_ports.lock().unwrap().clone();
    Ok(result)
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

trait IpV4Match {
    fn match_ipv4(&self) -> std::net::Ipv4Addr;
}

impl IpV4Match for IpAddr {
    fn match_ipv4(&self) -> std::net::Ipv4Addr {
        match self {
            IpAddr::V4(ip) => *ip,
            _ => std::net::Ipv4Addr::new(0,0,0,0),
        }
    }
}
