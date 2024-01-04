//! # 🌊 RPING
//!
//! A powerful command-line tool for executing TCP SYN flooding attacks.
//! Flood a target with a high volume of SYN packets to overwhelm and
//! disrupt its network.
//!
//! ## Quick Start
//!
//! Get started with the `rping` CLI by following these simple steps:
//!
//! 1. Install the `rping` tool using Cargo:
//!
//! ```bash
//! cargo install --locked --all-features rping
//! ```
//!
//! 2. Use the following options to perform SYN flooding attacks and customize the attack parameters:
//!
//! ```bash
//! rping -s 100 -t 127.0.0.1 -p 80 -h 8
//! ```
//!
//! ## Options
//!
//! | Option                  | Description                                               |
//! |-------------------------|-----------------------------------------------------------|
//! | `--size`                | Sets the length of SYN packets.                           |
//! | `--target`              | Specifies the target IP address to flood.                |
//! | `--port`                | Sets the target port number for the attack.               |
//! | `--threads`             | Sets the number of threads for the attack.               |
//!
//! ## GitHub Repository
//!
//! You can access the source code for this CLI tool on [GitHub](https://github.com/wiseaidev/rping).
//!
//! ## Contributing
//!
//! Contributions and feedback are welcome! If you'd like to contribute, report an issue, or suggest an enhancement,
//! please engage with the project on [GitHub](https://github.com/wiseaidev/rping).
//! Your contributions help improve this CLI tool for the community.
//!
//! **Let the SYN flood begin! 🌊**

#[cfg(feature = "cli")]
pub mod cli;
pub mod ip;
pub mod tcp;
pub mod utils;
