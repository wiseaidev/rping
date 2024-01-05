# 🌊 RPING

[![Crates.io](https://img.shields.io/crates/v/rping.svg)](https://crates.io/crates/rping)
[![docs](https://docs.rs/rping/badge.svg)](https://docs.rs/rping/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

```sh
rping 0.1.2
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

A powerful command-line tool for executing TCP SYN flooding attacks.
Flood a target with a high volume of SYN packets to overwhelm and
disrupt its network.
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

- Perform SYN flooding attacks with customizable parameters.
- Specify the length of SYN packets, target IP, and target port.
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

## 🎨 Options

| Option                   | Default Value | Description                                              |
|--------------------------|---------------|----------------------------------------------------------|
| `-s, --size`             | `1500`        | Set the length of SYN packets.                            |
| `-t, --target`           |               | Specify the target IP address to flood.                  |
| `-p, --port`             | `80`          | Set the target port number for the attack.               |
| `-h, --threads`          | `8`           | Set the number of threads for the attack.                |

## 🤝 Contributing

Contributions and feedback are welcome! If you'd like to contribute, report an issue, or suggest an enhancement, please engage with the project on [GitHub](https://github.com/wiseaidev/rping).
Your contributions help improve this CLI tool for the community.

## 📄 License

This project is licensed under the [MIT License](LICENSE).