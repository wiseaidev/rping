#[cfg(feature = "cli")]
use clap::builder::styling::{AnsiColor, Effects, Styles};
#[cfg(feature = "cli")]
use clap::Parser;

#[cfg(feature = "cli")]
fn styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Red.on_default() | Effects::BOLD)
        .usage(AnsiColor::Red.on_default() | Effects::BOLD)
        .literal(AnsiColor::Blue.on_default() | Effects::BOLD)
        .error(AnsiColor::Red.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Green.on_default())
}

#[cfg(feature = "cli")]
#[derive(Parser, Debug, Clone)]
#[command(
    author = "Mahmoud Harmouch",
    version,
    name = "rping",
    propagate_version = true,
    styles = styles(),
    help_template = r#"{before-help}{name} {version}
{about-with-newline}

{usage-heading} {usage}

{all-args}{after-help}

AUTHORS:
    {author}
"#,
    about=r#"
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

FEATURES:
  - Packet Length: Set the length of TCP packets to be sent.
  - Target IP: Specify the target IP address to flood.
  - Target Port: Set the target port number for the attack.
  - Threads: Set the number of threads for the attack.
  - TCP Flag: Specify the TCP flag (e.g., syn, ack, urg...).
  - Attack Duration: Set the attack duration in minutes.
  - Packets Number: Set the number of packets per thread.
  - Network Interface: Set the network interface to bind the socket to.

USAGE:
  rping [OPTIONS]

EXAMPLES:
  Perform SYN flooding attack for 1 minute:
    rping -s 100 -t 127.0.0.1 -p 80 -h 8 -f syn -n 1000000 -d 1 -i eth

For more information, visit: https://github.com/wiseaidev/rping
"#
)]
#[cfg(feature = "cli")]
pub struct Cli {
    #[arg(global = true, short, long)]
    pub verbose: bool,

    /// Target ip address.
    #[arg(short = 't', long = "target")]
    pub target: String,

    /// Target port number.
    #[arg(short = 'p', long = "port", default_value_t = 80)]
    pub port: usize,

    /// Length of SYN packets.
    #[arg(short = 's', long = "size", default_value_t = 1500)]
    pub size: usize,

    /// Number of threads.
    #[arg(short = 'h', long = "threads", default_value_t = 8)]
    pub threads: usize,

    /// TCP flag (e.g. syn, ack, urg...).
    #[arg(short = 'f', long = "flag", default_value_t = String::from("syn"))]
    pub flag: String,

    /// Attack duration (e.g. 2, 5) in minutes.
    #[arg(short = 'd', long = "duration", default_value_t = 1)]
    pub duration: usize,

    /// Number of packets (e.g. 100) per thread.
    #[arg(short = 'n', long = "number", default_value_t = 9223372036854775808)]
    pub number: usize,

    ///  The network interface to bind the socket to. Available only on iOS or macOS or tvOS or watchOS.
    #[arg(short = 'i', long = "iface", default_value_t = String::from("eth0"))]
    pub iface: String,
}
