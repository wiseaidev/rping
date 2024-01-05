use rand::Rng;
use std::time::SystemTime;

/// Represents the TCP header structure with its fields.
///
/// This struct follows the TCP header format.
/// Reference: https://github.com/wiseaidev/dark-web-rust/tree/main/chapter-1#16-decoding-tcp-packets
#[repr(C, packed)]
#[derive(Clone)]
pub struct TcpHeader {
    /// Source Port field.
    pub sport: u16,
    /// Destination Port field.
    pub dport: u16,
    /// Sequence Number field.
    pub seq: u16,
    /// Acknowledgment Number field.
    pub ack: u16,
    /// Data Offset (offset of the data in the TCP header), Reserved (always zero), and flags combined field.
    pub off_reserved_flags: u16,
    /// Window Size field.
    pub win: u16,
    /// Checksum field.
    pub sum: u16,
    /// Urgent Pointer field.
    pub urp: u16,
    /// Options field.
    pub opt: u16,
    /// Padding field.
    pub pad: u16,
}

/// Implements methods for the TcpHeader struct.
impl TcpHeader {
    /// Creates a new TCP header with default values.
    pub fn new(dest_port: u16) -> Self {
        let mut rng = rand::thread_rng();
        let data_offset = 20; // 5 words (20 bytes)
        let reserved = 0;
        let flags = 2; // 2 is the flag value for SYN
        let off_reserved_flags = (data_offset << 15) | (reserved << 12) | (flags << 7);

        TcpHeader {
            sport: (SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                % u16::MAX as u128) as u16,
            dport: dest_port.to_be(),
            seq: rng.gen::<u16>(),
            ack: rng.gen::<u16>(),
            off_reserved_flags,
            win: rng.gen::<u16>(),
            sum: rng.gen::<u16>(),
            urp: rng.gen::<u16>(),
            opt: rng.gen::<u16>(),
            pad: rng.gen::<u16>(),
        }
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
    ///     opt: 0,
    ///     pad: 0,
    /// };
    ///
    /// assert_eq!(tcp_header.as_bytes(), &[144, 31, 80, 0, 57, 48, 0, 0, 0, 80, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0]);
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
            off_reserved_flags: 0x0202,
            win: 1024,
            sum: 0,
            urp: 0,
            opt: 0,
            pad: 0,
        };

        assert_eq!(
            tcp_header.as_bytes(),
            &[144, 31, 80, 0, 57, 48, 0, 0, 2, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
