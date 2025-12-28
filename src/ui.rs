use console::style;

pub fn print_banner() {
    println!("{}", style("========================================").cyan());
    println!("{}", style("        PORTIFY: NETWORK SCANNER        ").bold().cyan());
    println!("{}", style("========================================").cyan());
}

pub fn print_results(ports: &mut Vec<u16>) {
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

fn get_service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP",
        53 => "DNS", 80 => "HTTP", 443 => "HTTPS", 445 => "SMB",
        3306 => "MySQL", 3389 => "RDP", 5432 => "PostgreSQL",
        8080 => "HTTP-Proxy", 27017 => "MongoDB",
        _ => "Unknown",
    }
}
