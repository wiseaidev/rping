use rand::Rng;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Represents the TCP header structure with its fields.
///
/// This struct follows the TCP header format.
/// Reference: [github.com/wiseaidev/dark-web-rust](https://github.com/wiseaidev/dark-web-rust/tree/main/chapter-1#16-decoding-tcp-packets)
#[derive(Clone, Debug)]
pub struct TcpHeader {
    /// Source Port field.
    pub sport: u16,
    /// Destination Port field.
    pub dport: u16,
    /// Sequence Number field.
    pub seq: u32,
    /// Acknowledgment Number field.
    pub ack: u32,
    /// Data Offset (offset of the data in the TCP header), Reserved (always zero), and flags combined field.
    pub off_reserved_flags: u16,
    /// Window Size field.
    pub win: u16,
    /// Checksum field.
    pub sum: u16,
    /// Urgent Pointer field.
    pub urp: u16,
    /// Options and Padding fields.
    pub opt_pad: u32,
}

/// Implements methods for the TcpHeader struct.
impl TcpHeader {
    /// Creates a new TCP header with default values.
    ///
    /// # Arguments
    ///
    /// * `src_ip` - Source IP address in network byte order (Big Endian).
    /// * `dest_ip` - Destination IP address in dotted-decimal notation (e.g., "192.168.1.1").
    /// * `dest_port` - Destination port number in network byte order (Big Endian).
    /// * `flag` - TCP flag string indicating the desired flag for the packet (e.g., "syn", "ack", "fin").
    ///
    /// # Returns
    ///
    /// (`TcpHeader`): A new TCP header instance with default values.
    ///
    /// # Examples
    ///
    /// ```
    /// use rping::tcp::TcpHeader;
    ///
    /// let src_ip: u32 = 0xC0A80001; // 192.168.0.1 in network byte order
    /// let dest_ip: &str = "192.168.1.1";
    /// let dest_port: u16 = 80;
    /// let flag: &str = "syn";
    ///
    /// let tcp_header = TcpHeader::new(src_ip, dest_ip, dest_port, flag);
    /// ```
    pub fn new(src_ip: u32, dest_ip: &str, dest_port: u16, flag: &str) -> Self {
        let mut rng = rand::thread_rng();
        let data_offset = 21; // 5 words (20 bytes)
        let reserved = 0;
        // Map flag string to corresponding value
        let flag_values: HashMap<&str, u16> = [
            ("fin", 1),
            ("syn", 2),
            ("rst", 4),
            ("psh", 8),
            ("ack", 16),
            ("urg", 32),
        ]
        .iter()
        .cloned()
        .collect();

        // Get the flag value or default to 2 if the flag is not recognized
        let flag = *flag_values.get(flag).unwrap_or(&2);
        let off_reserved_flags: u16 = (data_offset << 12) | ((reserved & 0b111111) << 6) | (flag);

        let mut tcp_header = Self {
            sport: rng.gen::<u16>(),
            dport: dest_port,
            seq: rng.gen::<u32>(),
            ack: rng.gen::<u32>(),
            off_reserved_flags,
            win: 0u16,
            sum: 0u16,
            urp: 1u16,
            opt_pad: 0,
        };

        // Calculate checksum and set it in the header
        tcp_header.sum = tcp_header.calculate_tcp_checksum(src_ip, dest_ip);
        tcp_header
    }

    /// Calculates the TCP checksum using the IPv4 pseudo-header and TCP header data.
    ///
    /// The TCP checksum is calculated based on the TCP header and an IPv4 pseudo-header,
    /// which includes the source and destination IP addresses. The algorithm involves
    /// summing 16-bit values and performing necessary carry propagation.
    ///
    /// # Arguments
    ///
    /// * `src_ip` - Source IP address in network byte order (Big Endian).
    /// * `dest_ip` - Destination IP address in dotted-decimal notation (e.g., "192.168.1.1").
    ///
    /// # Returns
    ///
    /// (`u16`): The calculated TCP checksum.
    ///
    /// # Examples
    ///
    /// ```
    /// use rping::tcp::TcpHeader;
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
    ///     opt_pad: 0,
    /// };
    ///
    /// let checksum = tcp_header.calculate_tcp_checksum(0xC0A80001, "192.168.1.1");
    /// assert_eq!(checksum, 55682);
    /// ```
    pub fn calculate_tcp_checksum(&self, src_ip: u32, dest_ip: &str) -> u16 {
        // TODO: fix algorithm
        let src_ip_bytes: [u8; 4] = src_ip.to_be_bytes();
        let dest_ip_bytes: [u8; 4] = Ipv4Addr::from_str(dest_ip).unwrap().octets();

        let mut csum: u32 = ((src_ip_bytes[0] as u32 + src_ip_bytes[2] as u32) << 8)
            + (src_ip_bytes[1] as u32 + src_ip_bytes[3] as u32);
        csum += ((dest_ip_bytes[0] as u32 + dest_ip_bytes[2] as u32) << 8)
            + (dest_ip_bytes[1] as u32 + dest_ip_bytes[3] as u32);

        let header_bytes = self.as_bytes();

        for i in (0..header_bytes.len()).step_by(2) {
            csum += (u32::from(header_bytes[i]) << 8) + u32::from(header_bytes[i + 1]);
        }

        while csum > 0xffff {
            csum = (csum >> 16) + (csum & 0xffff);
        }

        !csum as u16
    }

    /// Returns a byte slice representing the binary data of the TcpHeader.
    ///
    /// # Examples
    /// ```
    /// use rping::tcp::TcpHeader;
    ///
    /// let tcp_header = TcpHeader {
    ///     sport: 8080,
    ///     dport: 80,
    ///     seq: 12345,
    ///     ack: 0,
    ///     off_reserved_flags: 0x5000,
    ///     win: 1024,
    ///     sum: 0,
    ///     urp: 0,
    ///     opt_pad: 0,
    /// };
    ///
    /// assert_eq!(tcp_header.as_bytes(), &[31, 144, 0, 80, 0, 0, 48, 57, 0, 0, 0, 0, 80, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    /// ```
    /// Returns a byte slice representing the binary data of the TcpHeader.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(20);

        result.extend_from_slice(&self.sport.to_be_bytes());
        result.extend_from_slice(&self.dport.to_be_bytes());
        result.extend_from_slice(&self.seq.to_be_bytes());
        result.extend_from_slice(&self.ack.to_be_bytes());

        result.extend_from_slice(&self.off_reserved_flags.to_be_bytes());

        result.extend_from_slice(&self.win.to_be_bytes());

        result.extend_from_slice(&self.sum.to_be_bytes());
        result.extend_from_slice(&self.urp.to_be_bytes());
        result.extend_from_slice(&self.opt_pad.to_be_bytes());

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_header_as_bytes() {
        let tcp_header = TcpHeader {
            sport: 8080,
            dport: 80,
            seq: 12345,
            ack: 0,
            off_reserved_flags: 0x0202,
            win: 1024,
            sum: 0,
            urp: 0,
            opt_pad: 0,
        };

        assert_eq!(
            tcp_header.as_bytes(),
            &[31, 144, 0, 80, 0, 0, 48, 57, 0, 0, 0, 0, 2, 2, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn test_tcp_header_new() {
        let src_ip: u32 = 0xC0A80001;
        let dest_ip: &str = "192.168.1.1";
        let dest_port: u16 = 80;
        let flag: &str = "syn";

        let tcp_header = TcpHeader::new(src_ip, dest_ip, dest_port, flag);

        assert!(tcp_header.sport > 0);
        assert!(tcp_header.dport == dest_port);
        assert!(tcp_header.seq > 0);
        assert!(tcp_header.ack > 0);
        assert!(tcp_header.off_reserved_flags > 0);
        assert!(tcp_header.win == 0);
        assert!(tcp_header.sum > 0);
        assert!(tcp_header.urp == 1);
        assert!(tcp_header.opt_pad == 0);
    }

    #[test]
    fn test_tcp_header_calculate_tcp_checksum() {
        let tcp_header = TcpHeader {
            sport: 8080,
            dport: 80,
            seq: 12345,
            ack: 0,
            off_reserved_flags: 0x0202,
            win: 1024,
            sum: 0,
            urp: 0,
            opt_pad: 0,
        };

        let src_ip: u32 = 0xC0A80001;
        let dest_ip: &str = "192.168.1.1";

        let checksum = tcp_header.calculate_tcp_checksum(src_ip, dest_ip);
        assert_eq!(checksum, 10129);
    }
}
