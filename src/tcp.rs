/// Represents the TCP header structure with its fields.
#[derive(Clone)]
pub struct TcpHeader {
    /// Source Port field.
    pub sport: u16,
    /// Destination Port field.
    pub dport: u16,
    /// Sequence Number field.
    pub seq: u32,
    /// Acknowledgment Number field.
    pub ack: u32,
    /// Data Offset (offset of the data in the TCP header) and Reserved (always zero) combined field.
    pub offx2: u8,
    /// Flags field.
    pub flags: u8,
    /// Window Size field.
    pub win: u16,
    /// Checksum field.
    pub sum: u16,
    /// Urgent Pointer field.
    pub urp: u16,
}

/// Implements methods for the TcpHeader struct.
impl TcpHeader {
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
    ///     offx2: 0x50,
    ///     flags: 0x02,
    ///     win: 1024,
    ///     sum: 0,
    ///     urp: 0,
    /// };
    ///
    /// assert_eq!(tcp_header.as_bytes(), &[57, 48, 0, 0, 0, 0, 0, 0, 144, 31, 80, 0, 0, 4, 0, 0, 0, 0, 80, 2]);
    /// ```
    /// Returns a byte slice representing the binary data of the TcpHeader.
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
    fn test_tcp_header_as_bytes() {
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

        assert_eq!(
            tcp_header.as_bytes(),
            &[57, 48, 0, 0, 0, 0, 0, 0, 144, 31, 80, 0, 0, 4, 0, 0, 0, 0, 80, 2]
        );
    }
}
