//! Internal per-connection recv buffer-domain. Pins which provider/arming a
//! connection uses. Coarse by design: with_data / with_bytes / set_recv_sink
//! all share `CopyOrConsume` (they do not hold the provided buffer across
//! polls), so mixing them on one connection is allowed. Only `Forward` (the
//! long-hold recv_forward/splice path) is a distinct domain.
//!
//! Consumed by later phases; unused for now.
#![allow(dead_code)]

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) enum RecvDomain {
    #[default]
    CopyOrConsume,
    Forward,
}

impl RecvDomain {
    /// Whether this domain may use incremental (INC) provided buffers.
    /// Only the non-holding domain qualifies.
    pub fn inc_eligible(self) -> bool {
        matches!(self, RecvDomain::CopyOrConsume)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_is_copy_or_consume() {
        assert_eq!(RecvDomain::default(), RecvDomain::CopyOrConsume);
    }
    #[test]
    fn forward_is_not_inc_eligible() {
        assert!(!RecvDomain::Forward.inc_eligible());
        assert!(RecvDomain::CopyOrConsume.inc_eligible());
    }
}
