/// Represents the IP header structure with its fields.
#[derive(Debug)]
pub struct IpHeader {
    /// Version and Internet Header Length (IHL) combined field.
    pub version_ihl: u8,
    /// Time To Live (TTL) field.
    pub ttl: u8,
    /// Source IP address field.
    pub source_ip: u32,
    /// Destination IP address field.
    pub dest_ip: u32,
    /// Protocol field.
    pub protocol: u8,
    /// Length field.
    pub len: u16,
}
/// Implements methods for the IpHeader struct.
impl IpHeader {
    /// Returns a byte slice representing the binary data of the IpHeader.
    ///
    /// # Examples
    /// ```
    /// use rping::ip::IpHeader;
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
    /// assert_eq!(ip_header.as_bytes(), &[1, 0, 168, 192, 2, 0, 168, 192, 0, 0, 69, 64, 6, 127, 0, 0]);
    /// ```
    /// Returns a byte slice representing the binary data of the IpHeader.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_header_as_bytes() {
        let ip_header = IpHeader {
            version_ihl: 0x45,
            ttl: 64,
            source_ip: 0xC0A80001, // 192.168.0.1
            dest_ip: 0xC0A80002,   // 192.168.0.2
            protocol: 6,
            len: 0,
        };

        assert_eq!(
            ip_header.as_bytes(),
            &[1, 0, 168, 192, 2, 0, 168, 192, 0, 0, 69, 64, 6, 0, 0, 0]
        );
    }
}
