//! HTTP/2 flow control window tracking (RFC 7540 Section 6.9).

use crate::error::H2Error;

/// Default initial window size (RFC 7540 Section 6.9.2).
pub const DEFAULT_WINDOW_SIZE: i64 = 65535;

/// Tracks a send or receive flow control window.
#[derive(Debug, Clone)]
pub struct FlowControl {
    window: i64,
}

impl FlowControl {
    pub fn new(initial: i64) -> Self {
        Self { window: initial }
    }

    /// Current window size (may be negative after SETTINGS change).
    pub fn window(&self) -> i64 {
        self.window
    }

    /// Consume `amount` bytes from the window (for sending/receiving data).
    /// Returns error if the window would go below zero.
    pub fn consume(&mut self, amount: u32) -> Result<(), H2Error> {
        let new = self.window - i64::from(amount);
        if new < 0 {
            return Err(H2Error::FlowControlError);
        }
        self.window = new;
        Ok(())
    }

    /// Add `increment` to the window (from WINDOW_UPDATE).
    /// Returns error if the window would exceed 2^31 - 1.
    pub fn increase(&mut self, increment: u32) -> Result<(), H2Error> {
        let new = self.window + i64::from(increment);
        if new > 0x7fff_ffff {
            return Err(H2Error::FlowControlError);
        }
        self.window = new;
        Ok(())
    }

    /// Adjust the window after a SETTINGS change to INITIAL_WINDOW_SIZE.
    /// `delta` is (new_initial - old_initial), which can be negative.
    pub fn adjust(&mut self, delta: i64) -> Result<(), H2Error> {
        let new = self.window + delta;
        if new > 0x7fff_ffff {
            return Err(H2Error::FlowControlError);
        }
        self.window = new;
        Ok(())
    }
}

impl Default for FlowControl {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_consume_and_increase() {
        let mut fc = FlowControl::default();
        assert_eq!(fc.window(), 65535);
        fc.consume(1000).unwrap();
        assert_eq!(fc.window(), 64535);
        fc.increase(500).unwrap();
        assert_eq!(fc.window(), 65035);
    }

    #[test]
    fn consume_underflow() {
        let mut fc = FlowControl::new(100);
        assert!(fc.consume(101).is_err());
        assert_eq!(fc.window(), 100); // unchanged
    }

    #[test]
    fn increase_overflow() {
        let mut fc = FlowControl::new(0x7fff_ffff);
        assert!(fc.increase(1).is_err());
    }

    #[test]
    fn adjust_positive() {
        let mut fc = FlowControl::new(65535);
        fc.consume(1000).unwrap();
        assert_eq!(fc.window(), 64535);
        fc.adjust(1000).unwrap(); // new initial = old + 1000
        assert_eq!(fc.window(), 65535);
    }

    #[test]
    fn adjust_negative() {
        let mut fc = FlowControl::new(65535);
        fc.adjust(-100).unwrap();
        assert_eq!(fc.window(), 65435);
    }

    #[test]
    fn adjust_overflow() {
        let mut fc = FlowControl::new(0x7fff_fffe);
        assert!(fc.adjust(2).is_err());
    }
}
