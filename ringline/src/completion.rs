/// Msg flags for stream sends (`Send`/`SendMsg`/`SendMsgZc`, not the UDP
/// paths).
///
/// `MSG_DONTWAIT`: a send takes what the socket has room for and returns, and
/// never waits on an io-wq worker. A short result or `-EAGAIN` waits for room
/// behind a `POLLOUT` poll in `AsyncEventLoop::wait_for_room` (#605).
#[cfg(has_io_uring)]
pub(crate) const STREAM_SEND_FLAGS: i32 = libc::MSG_DONTWAIT;

/// Msg flags for the sends of a linked chain.
///
/// `MSG_WAITALL`: the kernel retries a short send, and fails the link if it
/// cannot finish, because the next SQE of the chain would otherwise follow a
/// gap (#734). A chain part on a full socket whose peer has half-closed waits
/// on an io-wq worker.
#[cfg(has_io_uring)]
pub(crate) const CHAIN_SEND_FLAGS: i32 = libc::MSG_WAITALL;

/// Operation tags encoded in the upper 8 bits of user_data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpTag {
    Send = 2,
    SendMsgZc = 3,
    Close = 4,
    Shutdown = 5,
    EventFdRead = 6,
    /// TLS-internal send (handshake, alert). Releases pool slot, no user callback.
    TlsSend = 7,
    /// Outbound TCP connect.
    Connect = 8,
    /// Async cancel (informational CQE only).
    Cancel = 10,
    /// Single-shot recvmsg for UDP sockets.
    RecvMsgUdp = 13,
    /// Copying sendmsg for UDP sockets.
    SendMsgUdp = 14,
    /// NVMe passthrough command (read, write, flush via IORING_OP_URING_CMD).
    NvmeCmd = 15,
    /// Direct I/O command (read, write, fsync via O_DIRECT + IORING_OP_READ/WRITE).
    DirectIo = 16,
    /// Filesystem I/O command (open, read, write, fsync, stat, rename, unlink, mkdir).
    Fs = 18,
    /// PollAdd on a pidfd for async child process exit notification.
    PidfdPoll = 19,
    /// `POLL_ADD` for `POLLOUT` on a connection whose send waits for room, one
    /// shot or multishot (`AsyncEventLoop::wait_for_room`). A connection arms
    /// one at a time, and its `ConnSendState` names the waiting send. Payload =
    /// connection generation.
    SendPollOut = 21,
    /// Multishot recv on a connected UDP socket (no peer info in CQE,
    /// kernel filters to the connected peer). Lighter than `RecvMsgUdp`.
    RecvUdp = 22,
    /// Single-shot send on a connected UDP socket (no msghdr, uses the
    /// socket's connected peer). Lighter than `SendMsgUdp`.
    SendUdp = 23,
    /// Coalesced copy send (plaintext or TLS ciphertext): one non-ZC
    /// `sendmsg` whose iovecs gather
    /// several queued per-connection sends. Payload = InFlightSendSlab index;
    /// the slab entry holds the backing pool slots, released on completion.
    SendMsgCoalesced = 24,
    /// Multishot accept on a listener the worker owns (merged accept mode).
    /// The `conn_index` field carries the **listener index**, not a
    /// connection: no slot exists yet when the SQE is submitted. Payload
    /// unused. One CQE per accepted connection; `IORING_CQE_F_MORE` says the
    /// arm is still live, and its absence means re-arm.
    AcceptMulti = 31,
    /// `IORING_OP_FIXED_FD_INSTALL` issued to recover a real fd for a
    /// connection being parked onto another worker (tier 3, #443). The
    /// payload carries the connection generation, so a CQE that outlived
    /// its slot is rejected.
    ParkInstall = 32,
    /// `shutdown(SHUT_RDWR)` hard-linked ahead of a connection's `Close`
    /// before Linux 6.13, so the peer gets its FIN even while older in-flight
    /// requests keep the socket from being released (#581), or `SO_LINGER`
    /// hard-linked ahead of it at worker exit (#607). Its completion is ignored;
    /// the `Close` CQE releases the slot.
    CloseShutdown = 33,
    /// `ASYNC_CANCEL` of every request on a connection's fixed file,
    /// hard-linked ahead of its `Close` from Linux 6.13 (#586), and at worker
    /// exit on every kernel, where a connection holding send slab entries gets
    /// it alone. Its completion is ignored; the `Close` CQE releases the slot.
    CloseCancel = 34,
    /// Plain (copying) `send` of the first non-empty unsent iovec of a
    /// zero-copy send whose `SendMsgZc` returned `-ENOMEM` (#642). It posts no
    /// notification. Payload = InFlightSendSlab index.
    SendMsgZcDrain = 35,
    /// Direct receive, on a plaintext TCP or Unix connection: a one-shot
    /// recv into the
    /// spare capacity of the connection's accumulator buffer. Payload =
    /// `Driver::direct_recvs` index, whose entry holds the buffer and the
    /// connection generation.
    RecvDirect = 36,
    /// `POLL_ADD` for `POLLRDHUP` on a direct connection, armed once when it
    /// opens. It completes on a peer FIN, a reset or a socket error, and
    /// not on data, so a connection whose task is not reading still sees
    /// the peer leave. Payload = connection generation.
    HangupPoll = 37,
    /// The non-blocking one-byte `MSG_PEEK` receive a completed hangup poll
    /// submits when no receive is in flight. Payload = connection generation.
    HangupPeek = 38,
}

impl OpTag {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            2 => Some(OpTag::Send),
            3 => Some(OpTag::SendMsgZc),
            4 => Some(OpTag::Close),
            5 => Some(OpTag::Shutdown),
            6 => Some(OpTag::EventFdRead),
            7 => Some(OpTag::TlsSend),
            8 => Some(OpTag::Connect),
            10 => Some(OpTag::Cancel),
            13 => Some(OpTag::RecvMsgUdp),
            14 => Some(OpTag::SendMsgUdp),
            15 => Some(OpTag::NvmeCmd),
            16 => Some(OpTag::DirectIo),
            18 => Some(OpTag::Fs),
            19 => Some(OpTag::PidfdPoll),
            21 => Some(OpTag::SendPollOut),
            22 => Some(OpTag::RecvUdp),
            23 => Some(OpTag::SendUdp),
            24 => Some(OpTag::SendMsgCoalesced),
            31 => Some(OpTag::AcceptMulti),
            32 => Some(OpTag::ParkInstall),
            33 => Some(OpTag::CloseShutdown),
            34 => Some(OpTag::CloseCancel),
            35 => Some(OpTag::SendMsgZcDrain),
            36 => Some(OpTag::RecvDirect),
            37 => Some(OpTag::HangupPoll),
            38 => Some(OpTag::HangupPeek),
            _ => None,
        }
    }

    /// Stable metric label for this tag.
    ///
    /// Paired with `from_u8` so the per-tag completion counters
    /// (`metrics::CQE_BY_TAG`) can be registered by walking the discriminant
    /// space: the names come from the enum rather than a parallel table that
    /// could drift out of step with it. `snake_case` because these become
    /// metric `op` labels.
    pub fn as_str(self) -> &'static str {
        match self {
            OpTag::Send => "send",
            OpTag::SendMsgZc => "send_msg_zc",
            OpTag::Close => "close",
            OpTag::Shutdown => "shutdown",
            OpTag::EventFdRead => "event_fd_read",
            OpTag::TlsSend => "tls_send",
            OpTag::Connect => "connect",
            OpTag::Cancel => "cancel",
            OpTag::RecvMsgUdp => "recv_msg_udp",
            OpTag::SendMsgUdp => "send_msg_udp",
            OpTag::NvmeCmd => "nvme_cmd",
            OpTag::DirectIo => "direct_io",
            OpTag::Fs => "fs",
            OpTag::PidfdPoll => "pidfd_poll",
            OpTag::SendPollOut => "send_poll_out",
            OpTag::RecvUdp => "recv_udp",
            OpTag::SendUdp => "send_udp",
            OpTag::SendMsgCoalesced => "send_msg_coalesced",
            OpTag::AcceptMulti => "accept_multi",
            OpTag::ParkInstall => "park_install",
            OpTag::CloseShutdown => "close_shutdown",
            OpTag::CloseCancel => "close_cancel",
            OpTag::SendMsgZcDrain => "send_msg_zc_drain",
            OpTag::RecvDirect => "recv_direct",
            OpTag::HangupPoll => "hangup_poll",
            OpTag::HangupPeek => "hangup_peek",
        }
    }
}

#[cfg(test)]
mod optag_label_tests {
    use super::OpTag;

    /// Every discriminant `from_u8` accepts must have a label, and no two tags
    /// may share one — a duplicate would silently merge two counters into one
    /// and read as "that operation never happened".
    #[test]
    fn labels_are_total_and_unique() {
        let mut seen = std::collections::HashMap::new();
        for v in 0..=u8::MAX {
            let Some(tag) = OpTag::from_u8(v) else {
                continue;
            };
            let label = tag.as_str();
            assert!(!label.is_empty(), "{tag:?} has an empty label");
            if let Some(prev) = seen.insert(label, tag) {
                panic!("{tag:?} and {prev:?} share the label {label:?}");
            }
        }
        // Sanity: the walk found the tags, rather than silently finding none.
        assert!(
            seen.len() >= 26,
            "expected the full tag set, found {}",
            seen.len()
        );
    }

    /// The label is the metric `op` value, so it must stay shell- and
    /// PromQL-safe: lowercase, digits and underscore only.
    #[test]
    fn labels_are_snake_case() {
        for v in 0..=u8::MAX {
            let Some(tag) = OpTag::from_u8(v) else {
                continue;
            };
            let l = tag.as_str();
            assert!(
                l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit()),
                "{tag:?} label {l:?} is not snake_case"
            );
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
pub struct UserData(pub(crate) u64);

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

    /// Pack a send-family payload: pool slot (or slab index) in the low 16
    /// bits, the connection generation's low 16 bits in the high 16.
    ///
    /// Completion handlers compare the packed generation against the
    /// connection's current generation before touching per-connection state:
    /// a Send CQE can outlive its connection slot (e.g. a close submitted
    /// with a send still in flight), and after the index is reused the CQE
    /// would otherwise be misattributed to the new occupant. 16 truncated
    /// bits suffice — a false match needs 65536 reallocations of one index
    /// while a single CQE is in flight.
    #[inline]
    pub fn send_payload(slot: u16, generation: u32) -> u32 {
        (slot as u32) | ((generation & 0xFFFF) << 16)
    }

    /// Unpack the slot/slab half of a send-family payload.
    #[inline]
    pub fn send_payload_slot(payload: u32) -> u16 {
        payload as u16
    }

    /// Unpack the truncated-generation half of a send-family payload.
    #[inline]
    pub fn send_payload_gen(payload: u32) -> u16 {
        (payload >> 16) as u16
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

    /// The send-family payload truncates the connection generation to 16
    /// bits, and the completion handlers compare the packed half against the
    /// live generation masked the same way. Every event-loop test recycles a
    /// slot only a handful of times, so none of them ever reaches a generation
    /// where the truncation actually bites; reaching 0x8000 through
    /// `ConnectionTable` would take 32768 recycles. These pin the boundary
    /// directly.
    ///
    /// Found because a mutation that narrowed `send_payload`'s mask from
    /// 0xFFFF to 0x7FFF failed no test at all: the generation those tests use
    /// (0x2A3) fits in 15 bits, so both masks agree and the mutation was a
    /// no-op. The encoding was fine; the coverage was not.
    #[test]
    fn send_payload_truncates_the_generation_at_sixteen_bits() {
        for generation in [
            0u32,
            1,
            0x7FFF,
            0x8000, // first value the 15- and 16-bit masks disagree on
            0xFFFF,
            0x1_0000, // truncates to 0
            0x1_2A3,
            u32::MAX,
        ] {
            let payload = UserData::send_payload(0xBEEF, generation);
            assert_eq!(
                UserData::send_payload_slot(payload),
                0xBEEF,
                "slot half corrupted at generation {generation:#x}"
            );
            assert_eq!(
                UserData::send_payload_gen(payload),
                (generation & 0xFFFF) as u16,
                "generation half is not the low 16 bits at {generation:#x}"
            );
        }
    }

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
        let ud = UserData::encode(OpTag::Send, 0, 0);
        assert_eq!(ud.tag(), Some(OpTag::Send));
        assert_eq!(ud.conn_index(), 0);
        assert_eq!(ud.payload(), 0);
    }

    #[test]
    fn max_conn_index() {
        let max_conn = (1u32 << 24) - 1;
        let ud = UserData::encode(OpTag::Send, max_conn, 0xFFFF_FFFF);
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
