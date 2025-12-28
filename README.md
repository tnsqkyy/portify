# Portify

A high-performance TCP SYN scanner written in Rust.

## Features
- **Raw SYN Scan**: Fast and stealthy using raw sockets.
- **Asynchronous**: Multi-threaded sender/receiver tasks.
- **Rate Limited**: Hard-coded at 3000 PPS for stability.
- **Clean CLI**: Simple positional arguments.

## Installation
```bash
git clone https://github.com/tnsqkyy/portify
cd portify
cargo build --release
```

## Usage
Requires root privileges for raw socket access.

```bash
sudo ./target/release/portify <IP> [START] [END]
```

### Examples
```bash
# Default (Ports 1-1000)
sudo ./target/release/portify 1.1.1.1

# Custom range
sudo ./target/release/portify 8.8.8.8 1 5000
```

## License
This project is licensed under the MIT License.
