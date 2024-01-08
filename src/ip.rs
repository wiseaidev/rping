use crate::tcp::TcpHeader;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Represents the IP header structure with its fields.
///
/// This struct follows the IP header format.
/// Reference: [github.com/wiseaidev/dark-web-rust](https://github.com/wiseaidev/dark-web-rust/tree/main/chapter-1#13-the-ip-header-struct)
#[derive(Debug)]
pub struct IpHeader {
    /// Version and Internet Header Length (IHL) combined field.
    pub version_ihl: u8,
    /// Type of Service (TOS) field.
    pub tos: u8,
    /// Length field.
    pub len: u16,
    /// Identification field.
    pub id: u16,
    /// Fragment Offset field.
    pub offset: u16,
    /// Time To Live (TTL) field.
    pub ttl: u8,
    /// Protocol field.
    pub protocol: u8,
    /// Header Checksum field.
    pub sum: u16,
    /// Source IP address field.
    pub src: u32,
    /// Destination IP address field.
    pub dst: u32,
}
/// Implements methods for the IpHeader struct.
impl IpHeader {
    /// Constructs an IP header with the given source IP and computes the length and checksum.
    ///
    /// # Arguments
    ///
    /// * `source_ip` - The source IP address.
    /// * `dest_ip` - The target ip.
    ///
    /// # Returns
    ///
    /// (`IpHeader`): The IP header with calculated length and checksum.
    ///
    /// # Examples
    ///
    /// ```
    /// use rping::utils::generate_random_ip;
    /// use rping::ip::IpHeader;
    ///
    /// let source_ip = generate_random_ip();
    /// let ip_header = IpHeader::new(source_ip, "192.168.1.10");
    /// // Ensure that relevant fields have been initialized properly.
    /// assert_eq!(ip_header.version_ihl, (4 << 4) | 5);
    /// assert_eq!(ip_header.protocol, 6);
    /// ```
    pub fn new(source_ip: u32, dest_ip: &str) -> Self {
        let mut ip_header = Self {
            version_ihl: 69,
            tos: 0,
            len: 0,
            id: 0,
            offset: 0,
            ttl: 50,
            protocol: 6,
            sum: 0,
            src: source_ip,
            dst: Ipv4Addr::from_str(dest_ip).unwrap().into(),
        };

        // Calculate the total length (IP header + TCP header)
        ip_header.len = (std::mem::size_of::<IpHeader>() + std::mem::size_of::<TcpHeader>()) as u16;

        ip_header
    }

    /// Returns a byte slice representing the binary data of the IpHeader.
    ///
    /// # Examples
    /// ```
    /// use rping::ip::IpHeader;
    ///
    /// let ip_header = IpHeader {
    ///     version_ihl: 0x45,
    ///     tos: 0,
    ///     len: 20,
    ///     id: 0,
    ///     offset: 0,
    ///     ttl: 64,
    ///     protocol: 6,
    ///     sum: 127,
    ///     src: 0xC0A80001, // 192.168.0.1
    ///     dst: 0xC0A80002, // 192.168.0.2
    /// };
    ///
    /// assert_eq!(
    ///     ip_header.as_bytes(),
    ///     &[69, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 127, 192, 168, 0, 1, 192, 168, 0, 2]
    /// );
    /// ```
    /// Returns a byte slice representing the binary data of the IpHeader.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);
        bytes.push(self.version_ihl);
        bytes.push(self.tos);
        bytes.extend_from_slice(&self.len.to_be_bytes());
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.offset.to_be_bytes());
        bytes.push(self.ttl);
        bytes.push(self.protocol);
        bytes.extend_from_slice(&self.sum.to_be_bytes());
        bytes.extend_from_slice(&self.src.to_be_bytes());
        bytes.extend_from_slice(&self.dst.to_be_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_header_as_bytes() {
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

        assert_eq!(
            ip_header.as_bytes(),
            &[69, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 192, 168, 0, 1, 192, 168, 0, 2]
        );
    }
}
