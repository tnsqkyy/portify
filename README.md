# Portify

A blazing fast, multi-threaded TCP SYN port scanner written in Rust. It uses Raw Sockets to bypass the OS stack for maximum performance (similar to nmap -sS).

## Features
- Raw SYN Scan: Stealthy and fast.
- Multi-threaded: Separate Sender/Receiver threads.
- Interactive CLI: Progress bar and colored output.

## Usage

Requires sudo for raw socket access.

```bash
cargo build --release
sudo ./target/release/portify
```

## Disclaimer
For educational purposes only. Do not scan unauthorized networks.

## License
This project is licensed under the MIT License.
