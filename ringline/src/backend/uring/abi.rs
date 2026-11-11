//! The parts of the io_uring kernel ABI the driver reads and writes: the
//! timespec a TIMEOUT points at, the flags on a completion, and the layout
//! of a multishot `recvmsg` buffer.
//!
//! Outside `engine/uring.rs`, only tests use the `io_uring` crate;
//! the tests here check these definitions against it.

/// `struct __kernel_timespec`, which a TIMEOUT operation points at.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

impl Timespec {
    pub(crate) const fn new() -> Self {
        Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }

    /// Seconds past `i64::MAX` are clamped to it: the kernel refuses a
    /// negative `tv_sec` with `EINVAL`, and a timeout that far out never
    /// expires either way.
    pub(crate) const fn sec(mut self, sec: u64) -> Self {
        self.tv_sec = if sec > i64::MAX as u64 {
            i64::MAX
        } else {
            sec as i64
        };
        self
    }

    pub(crate) const fn nsec(mut self, nsec: u32) -> Self {
        self.tv_nsec = nsec as i64;
        self
    }
}

/// The flags a completion carries (`IORING_CQE_F_*`).
pub(crate) mod cqueue {
    const F_BUFFER: u32 = 1 << 0;
    const F_MORE: u32 = 1 << 1;
    const F_SOCK_NONEMPTY: u32 = 1 << 2;
    const F_NOTIF: u32 = 1 << 3;
    const F_BUF_MORE: u32 = 1 << 4;
    const BUFFER_SHIFT: u32 = 16;

    /// The provided buffer the completion consumed, if any.
    pub(crate) fn buffer_select(flags: u32) -> Option<u16> {
        if flags & F_BUFFER != 0 {
            Some((flags >> BUFFER_SHIFT) as u16)
        } else {
            None
        }
    }

    /// More completions follow for this request (a multishot is still
    /// armed, or a zero-copy send's notification is still to come).
    pub(crate) fn more(flags: u32) -> bool {
        flags & F_MORE != 0
    }

    /// The completion is a zero-copy send's notification.
    pub(crate) fn notif(flags: u32) -> bool {
        flags & F_NOTIF != 0
    }

    /// The socket still had data queued after this receive completed
    /// (`IORING_CQE_F_SOCK_NONEMPTY`).
    #[cfg_attr(not(test), allow(dead_code))] // first driver use lands with #622's promotion
    pub(crate) fn sock_nonempty(flags: u32) -> bool {
        flags & F_SOCK_NONEMPTY != 0
    }

    /// The provided buffer the completion used has room left, and the
    /// kernel keeps consuming it (`IORING_CQE_F_BUF_MORE`, incremental
    /// rings only).
    #[cfg_attr(not(test), allow(dead_code))] // first driver use lands with #622 step 4
    pub(crate) fn buf_more(flags: u32) -> bool {
        flags & F_BUF_MORE != 0
    }
}

/// `struct io_uring_recvmsg_out`, at the start of each buffer a multishot
/// `recvmsg` fills.
#[derive(Clone, Copy)]
#[repr(C)]
struct RecvMsgHeader {
    namelen: u32,
    controllen: u32,
    payloadlen: u32,
    flags: u32,
}

/// One datagram in a multishot `recvmsg` buffer. The buffer holds the
/// header, then `msg_namelen` bytes for the name, then `msg_controllen`
/// bytes for control data, then the payload.
pub(crate) struct RecvMsgOut<'buf> {
    header: RecvMsgHeader,
    name_field_len: usize,
    name_data: &'buf [u8],
    control_data: &'buf [u8],
    payload_data: &'buf [u8],
}

impl<'buf> RecvMsgOut<'buf> {
    const DATA_START: usize = std::mem::size_of::<RecvMsgHeader>();

    /// Split `buffer` as the kernel laid it out for an arm whose template
    /// was `msghdr` (only its `msg_namelen` and `msg_controllen` matter).
    /// Fails when `buffer` is shorter than the header and the two fields.
    pub(crate) fn parse(buffer: &'buf [u8], msghdr: &libc::msghdr) -> Result<Self, ()> {
        let name_field_len = msghdr.msg_namelen as usize;
        // `msg_controllen` is `size_t` on glibc and Android, and `socklen_t`
        // on musl and the BSDs (macOS included).
        #[allow(clippy::unnecessary_cast)]
        let control_field_len = msghdr.msg_controllen as usize;
        if Self::DATA_START
            .checked_add(name_field_len)
            .and_then(|n| n.checked_add(control_field_len))
            .is_none_or(|header_len| buffer.len() < header_len)
        {
            return Err(());
        }
        // Safety: the length check above covers the header.
        let header = unsafe { buffer.as_ptr().cast::<RecvMsgHeader>().read_unaligned() };

        // The header gives the full lengths; the name and control data may
        // have been truncated to their fields, and the payload to the rest of
        // the buffer.
        let name_start = Self::DATA_START;
        let name_end = name_start + (header.namelen as usize).min(name_field_len);
        let control_start = name_start + name_field_len;
        let control_end = control_start + (header.controllen as usize).min(control_field_len);
        let payload_start = control_start + control_field_len;
        let payload_end =
            payload_start + (header.payloadlen as usize).min(buffer.len() - payload_start);
        Ok(RecvMsgOut {
            header,
            name_field_len,
            name_data: &buffer[name_start..name_end],
            control_data: &buffer[control_start..control_end],
            payload_data: &buffer[payload_start..payload_end],
        })
    }

    /// The sender's name did not fit its field.
    pub(crate) fn is_name_data_truncated(&self) -> bool {
        self.header.namelen as usize > self.name_field_len
    }

    pub(crate) fn name_data(&self) -> &'buf [u8] {
        self.name_data
    }

    /// The control data did not fit its field (`MSG_CTRUNC`).
    pub(crate) fn is_control_data_truncated(&self) -> bool {
        self.header.flags & libc::MSG_CTRUNC as u32 != 0
    }

    pub(crate) fn control_data(&self) -> &'buf [u8] {
        self.control_data
    }

    /// The payload did not fit the buffer (`MSG_TRUNC`).
    pub(crate) fn is_payload_truncated(&self) -> bool {
        self.header.flags & libc::MSG_TRUNC as u32 != 0
    }

    pub(crate) fn payload_data(&self) -> &'buf [u8] {
        self.payload_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel refuses a negative `tv_sec`; seconds past `i64::MAX`
    /// clamp to it (#836).
    #[test]
    fn timespec_seconds_clamp_to_i64_max() {
        assert_eq!(Timespec::new().sec(u64::MAX).tv_sec, i64::MAX);
        assert_eq!(Timespec::new().sec(i64::MAX as u64).tv_sec, i64::MAX);
        assert_eq!(Timespec::new().sec(5).tv_sec, 5);
    }

    #[test]
    fn timespec_matches_the_kernel_layout() {
        assert_eq!(
            std::mem::size_of::<Timespec>(),
            std::mem::size_of::<io_uring::types::Timespec>()
        );
        assert_eq!(
            std::mem::align_of::<Timespec>(),
            std::mem::align_of::<io_uring::types::Timespec>()
        );
        let ours = Timespec::new().sec(12).nsec(345_678_901);
        let theirs = io_uring::types::Timespec::new().sec(12).nsec(345_678_901);
        let bytes = |p: *const u8| unsafe { std::slice::from_raw_parts(p, 16).to_vec() };
        assert_eq!(
            bytes(&ours as *const Timespec as *const u8),
            bytes(&theirs as *const io_uring::types::Timespec as *const u8)
        );
    }

    #[test]
    fn cqe_flags_read_like_the_io_uring_crate() {
        let samples = [
            0u32,
            1,
            2,
            3,
            4,
            8,
            9,
            10,
            11,
            0x10,
            0x14,
            0x0007_0001,
            0xffff_0003,
            0x1234_000b,
            u32::MAX,
        ];
        for f in samples {
            assert_eq!(
                cqueue::buffer_select(f),
                io_uring::cqueue::buffer_select(f),
                "{f:#x}"
            );
            assert_eq!(cqueue::more(f), io_uring::cqueue::more(f), "{f:#x}");
            assert_eq!(cqueue::notif(f), io_uring::cqueue::notif(f), "{f:#x}");
            assert_eq!(
                cqueue::sock_nonempty(f),
                io_uring::cqueue::sock_nonempty(f),
                "{f:#x}"
            );
            assert_eq!(
                cqueue::buf_more(f),
                io_uring::cqueue::buffer_more(f),
                "{f:#x}"
            );
        }
    }

    const NAME_FIELD: usize = 16;
    const CONTROL_FIELD: usize = 32;

    fn buffer(
        name: &[u8],
        namelen: u32,
        control: &[u8],
        controllen: u32,
        payload: &[u8],
        payloadlen: u32,
        flags: u32,
    ) -> Vec<u8> {
        let mut b = Vec::new();
        for v in [namelen, controllen, payloadlen, flags] {
            b.extend_from_slice(&v.to_ne_bytes());
        }
        let mut field = |data: &[u8], len: usize| {
            let mut f = data.to_vec();
            f.resize(len, 0xee);
            b.extend_from_slice(&f);
        };
        field(name, NAME_FIELD);
        field(control, CONTROL_FIELD);
        b.extend_from_slice(payload);
        b
    }

    #[test]
    fn recvmsg_out_splits_like_the_io_uring_crate() {
        let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
        msghdr.msg_namelen = NAME_FIELD as u32;
        msghdr.msg_controllen = CONTROL_FIELD as _;
        let cases = [
            buffer(b"name", 4, b"ctl", 3, b"payload", 7, 0),
            // Name and control truncated to their fields.
            buffer(&[1; 16], 28, &[2; 32], 64, b"p", 1, libc::MSG_CTRUNC as u32),
            // Payload longer than the buffer holds.
            buffer(b"", 0, b"", 0, b"abc", 4096, libc::MSG_TRUNC as u32),
            // A name exactly filling its field is not truncated.
            buffer(&[1; NAME_FIELD], NAME_FIELD as u32, b"", 0, b"p", 1, 0),
            // Control data longer than its field, without MSG_CTRUNC:
            // truncation is read from the flag.
            buffer(b"", 0, &[2; CONTROL_FIELD], 64, b"p", 1, 0),
            // Empty payload.
            buffer(b"n", 1, b"", 0, b"", 0, 0),
            // Too short for the fields.
            vec![0u8; 20],
        ];
        for (i, b) in cases.iter().enumerate() {
            let ours = RecvMsgOut::parse(b, &msghdr);
            let theirs = io_uring::types::RecvMsgOut::parse(b, &msghdr);
            match (ours, theirs) {
                (Ok(o), Ok(t)) => {
                    assert_eq!(o.name_data(), t.name_data(), "case {i}");
                    assert_eq!(o.control_data(), t.control_data(), "case {i}");
                    assert_eq!(o.payload_data(), t.payload_data(), "case {i}");
                    assert_eq!(
                        o.is_name_data_truncated(),
                        t.is_name_data_truncated(),
                        "case {i}"
                    );
                    assert_eq!(
                        o.is_control_data_truncated(),
                        t.is_control_data_truncated(),
                        "case {i}"
                    );
                    assert_eq!(
                        o.is_payload_truncated(),
                        t.is_payload_truncated(),
                        "case {i}"
                    );
                }
                (Err(()), Err(())) => {}
                (o, t) => panic!("case {i}: ours ok={} theirs ok={}", o.is_ok(), t.is_ok()),
            }
        }
    }
}
