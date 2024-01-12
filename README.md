# 🌊 RPING

[![Crates.io](https://img.shields.io/crates/v/rping.svg)](https://crates.io/crates/rping)
[![docs](https://docs.rs/rping/badge.svg)](https://docs.rs/rping/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

```sh
rping 0.1.5
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄        ▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░▌      ▐░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀ ▐░▌░▌     ▐░▌▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌       ▐░▌▐░▌       ▐░▌     ▐░▌     ▐░▌▐░▌    ▐░▌▐░▌          
▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░▌ ▐░▌   ▐░▌▐░▌ ▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░▌  ▐░▌  ▐░▌▐░▌▐░░░░░░░░▌
▐░█▀▀▀▀█░█▀▀ ▐░█▀▀▀▀▀▀▀▀▀      ▐░▌     ▐░▌   ▐░▌ ▐░▌▐░▌ ▀▀▀▀▀▀█░▌
▐░▌     ▐░▌  ▐░▌               ▐░▌     ▐░▌    ▐░▌▐░▌▐░▌       ▐░▌
▐░▌      ▐░▌ ▐░▌           ▄▄▄▄█░█▄▄▄▄ ▐░▌     ▐░▐░▌▐░█▄▄▄▄▄▄▄█░▌
▐░▌       ▐░▌▐░▌          ▐░░░░░░░░░░░▌▐░▌      ▐░░▌▐░░░░░░░░░░░▌
 ▀         ▀  ▀            ▀▀▀▀▀▀▀▀▀▀▀  ▀        ▀▀  ▀▀▀▀▀▀▀▀▀▀▀ 

🌊 RPING CLI
============

A powerful command-line tool for executing TCP flags flooding attacks.
Customize attacks with options like packet length, number of threads,
and TCP flags for efficient network disruption.
```

> 🚀 **rping**: A robust, fully anonymous, Rust-based CLI for any TCP flag flooding attacks.

## 📖 Table of Contents

- [Installation](#-installation)
- [Features](#-features)
- [Usage](#-usage)
- [Options](#-options)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Installation

To install `rping`, use the following Cargo command:

```bash
cargo install --locked --all-features rping
```

Once installed, run the following command:

```bash
sudo setcap cap_net_raw+ep ~/.cargo/bin/rping
```

This will set the [`CAP_NET_RAW` capability](https://man7.org/linux/man-pages/man7/capabilities.7.html) and make `rping` run with elevated privileges.

## ✨ Features

- Perform any TCP flag, e.g. syn, flooding attacks with customizable parameters.
- Specify the length of tcp packets, target IP, target port, number of packets and the attack duration.
- Multi-threaded execution for increased efficiency.

## 🚗 Usage

Learn how to use `rping` and explore its features with the following examples:

### Perform a SYN flooding attack:

```bash
rping -t 127.0.0.1 -p 80
```

### Specify the packet length:

```bash
rping -s 150 -t 127.0.0.1 -p 443
```

### Use multiple threads:

```bash
rping -s 1500 -t 127.0.0.1 -p 8080 -h 16
```

### Specify the TCP flag (e.g., ack, urg):

```bash
rping -f ack -t 127.0.0.1 -p 8080
```

### Set the attack duration in minutes:

```bash
rping -d 5 -t 127.0.0.1 -p 80
```

### Set the number of packets per thread:

```bash
rping -n 10000 -t 127.0.0.1 -p 8080
```

### Set the network interface:

```bash
rping -n 10000 -t 127.0.0.1 -p 8080 -i eth0
```

## 🎨 Options

| Option                   | Default Value | Description                                              |
|--------------------------|---------------|----------------------------------------------------------|
| `-s, --size`             | `1500`        | Set the length of SYN packets.                            |
| `-t, --target`           |               | Specify the target IP address to flood.                  |
| `-p, --port`             | `80`          | Set the target port number for the attack.               |
| `-h, --threads`          | `8`           | Set the number of threads for the attack.                |
| `-f, --flag`             | `syn`         | Specify the TCP flag (e.g., syn, ack, urg...).            |
| `-d, --duration`         | `1`           | Set the attack duration in minutes.                      |
| `-n, --number`           | `2^63` | Set the number of packets per thread.            |
| `-i, --iface`           | `eth0` | Set the network interface to bind the socket to.        |

> [!NOTE]
Configuring the network interface is restricted to iOS, macOS, tvOS, or watchOS due to limitations in `socket2`.

## 🤝 Contributing

Contributions and feedback are welcome! If you'd like to contribute, report an issue, or suggest an enhancement, please engage with the project on [GitHub](https://github.com/wiseaidev/rping).
Your contributions help improve this CLI tool for the community.

## 📄 License

This project is licensed under the [MIT License](LICENSE).