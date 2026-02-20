/// Operation tags encoded in the upper 8 bits of user_data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpTag {
    RecvMulti = 0,
    Send = 2,
    SendMsgZc = 3,
    Close = 4,
    Shutdown = 5,
    EventFdRead = 6,
    /// TLS-internal send (handshake, alert). Releases pool slot, no user callback.
    #[cfg(feature = "tls")]
    TlsSend = 7,
    /// Outbound TCP connect.
    Connect = 8,
    /// Timeout (e.g., connect timeout).
    Timeout = 9,
    /// Async cancel (informational CQE only).
    Cancel = 10,
    /// Periodic tick timeout to prevent submit_and_wait from blocking indefinitely.
    TickTimeout = 11,
    /// Standalone timer (sleep/timeout) for async tasks.
    Timer = 12,
    /// Single-shot recvmsg for UDP sockets.
    RecvMsgUdp = 13,
    /// Copying sendmsg for UDP sockets.
    SendMsgUdp = 14,
    /// NVMe passthrough command (read, write, flush via IORING_OP_URING_CMD).
    NvmeCmd = 15,
    /// Direct I/O command (read, write, fsync via O_DIRECT + IORING_OP_READ/WRITE).
    DirectIo = 16,
}

impl OpTag {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(OpTag::RecvMulti),
            2 => Some(OpTag::Send),
            3 => Some(OpTag::SendMsgZc),
            4 => Some(OpTag::Close),
            5 => Some(OpTag::Shutdown),
            6 => Some(OpTag::EventFdRead),
            #[cfg(feature = "tls")]
            7 => Some(OpTag::TlsSend),
            8 => Some(OpTag::Connect),
            9 => Some(OpTag::Timeout),
            10 => Some(OpTag::Cancel),
            11 => Some(OpTag::TickTimeout),
            12 => Some(OpTag::Timer),
            13 => Some(OpTag::RecvMsgUdp),
            14 => Some(OpTag::SendMsgUdp),
            15 => Some(OpTag::NvmeCmd),
            16 => Some(OpTag::DirectIo),
            _ => None,
        }
    }
}

/// Encoded user_data for io_uring CQE identification.
///
/// Layout (64-bit):
/// ```text
/// Bits 63..56: OpTag (8 bits)
/// Bits 55..32: ConnIndex (24 bits, max 16M connections)
/// Bits 31..0:  Payload (32 bits, buffer index or seq number)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserData(pub u64);

impl UserData {
    const TAG_SHIFT: u64 = 56;
    const CONN_SHIFT: u64 = 32;
    const TAG_MASK: u64 = 0xFF << Self::TAG_SHIFT;
    const CONN_MASK: u64 = 0x00FF_FFFF << Self::CONN_SHIFT;
    const PAYLOAD_MASK: u64 = 0xFFFF_FFFF;

    /// Encode an operation tag, connection index, and payload into user_data.
    #[inline]
    pub fn encode(tag: OpTag, conn_index: u32, payload: u32) -> Self {
        debug_assert!(conn_index < (1 << 24), "conn_index exceeds 24 bits");
        let v = ((tag as u64) << Self::TAG_SHIFT)
            | (((conn_index as u64) & 0x00FF_FFFF) << Self::CONN_SHIFT)
            | (payload as u64);
        UserData(v)
    }

    /// Decode the operation tag.
    #[inline]
    pub fn tag(self) -> Option<OpTag> {
        let raw = ((self.0 & Self::TAG_MASK) >> Self::TAG_SHIFT) as u8;
        OpTag::from_u8(raw)
    }

    /// Decode the connection index.
    #[inline]
    pub fn conn_index(self) -> u32 {
        ((self.0 & Self::CONN_MASK) >> Self::CONN_SHIFT) as u32
    }

    /// Decode the payload.
    #[inline]
    pub fn payload(self) -> u32 {
        (self.0 & Self::PAYLOAD_MASK) as u32
    }

    /// Get the raw u64 value.
    #[inline]
    pub fn raw(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_tags() {
        for tag_val in 0..=10u8 {
            let tag = match OpTag::from_u8(tag_val) {
                Some(t) => t,
                None => continue,
            };
            let conn = 0x00AB_CDEFu32 & 0x00FF_FFFF;
            let payload = 0xDEAD_BEEFu32;
            let ud = UserData::encode(tag, conn, payload);
            assert_eq!(ud.tag(), Some(tag));
            assert_eq!(ud.conn_index(), conn);
            assert_eq!(ud.payload(), payload);
        }
    }

    #[test]
    fn zero_values() {
        let ud = UserData::encode(OpTag::RecvMulti, 0, 0);
        assert_eq!(ud.tag(), Some(OpTag::RecvMulti));
        assert_eq!(ud.conn_index(), 0);
        assert_eq!(ud.payload(), 0);
    }

    #[test]
    fn max_conn_index() {
        let max_conn = (1u32 << 24) - 1;
        let ud = UserData::encode(OpTag::RecvMulti, max_conn, 0xFFFF_FFFF);
        assert_eq!(ud.conn_index(), max_conn);
        assert_eq!(ud.payload(), 0xFFFF_FFFF);
    }

    #[test]
    fn invalid_tag() {
        // Manually craft user_data with invalid tag
        let ud = UserData(0xFF << 56);
        assert_eq!(ud.tag(), None);
    }
}
