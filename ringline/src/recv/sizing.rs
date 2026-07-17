//! Pure per-connection recv-size policy: an EWMA of observed arrival sizes plus
//! proactive `NeedAtLeast` hints, converted to a target buffer size with
//! hysteresis so a class change cannot flap on a single sample. No I/O.
//!
//! Nothing outside this module consumes `SizingPolicy` yet — it lands ahead
//! of the phases that wire it into recv buffer allocation.
#![allow(dead_code)]

/// Configuration for [`SizingPolicy`]. Fixed-point alpha/downshift avoid float
/// determinism concerns and are cheap on the hot path.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SizingConfig {
    pub(crate) min: usize,
    pub(crate) max: usize,
    /// EWMA smoothing factor alpha = alpha_num / alpha_den (0 < alpha <= 1).
    pub(crate) alpha_num: u32,
    pub(crate) alpha_den: u32,
    /// Downshift only when the EWMA falls below current_target * (down_num/down_den).
    pub(crate) downshift_num: u32,
    pub(crate) downshift_den: u32,
}

#[derive(Debug)]
pub(crate) struct SizingPolicy {
    cfg: SizingConfig,
    /// EWMA of observed sizes, in bytes.
    ewma: usize,
    /// Current target buffer size (bytes), moved with hysteresis.
    target: usize,
}

impl SizingPolicy {
    pub fn new(cfg: SizingConfig) -> Self {
        debug_assert!(cfg.min <= cfg.max, "SizingConfig: min must be <= max");
        debug_assert!(
            cfg.alpha_den != 0 && cfg.alpha_num >= 1 && cfg.alpha_num <= cfg.alpha_den,
            "SizingConfig: alpha_num/alpha_den must satisfy 0 < alpha <= 1"
        );
        debug_assert!(
            cfg.downshift_den != 0 && cfg.downshift_num <= cfg.downshift_den,
            "SizingConfig: downshift fraction must be in (0, 1]"
        );
        SizingPolicy {
            ewma: cfg.min,
            target: cfg.min,
            cfg,
        }
    }

    /// Record an observed arrival/message size and re-evaluate the target.
    pub fn observe(&mut self, size: usize) {
        // ewma += alpha * (size - ewma), fixed-point.
        // Fixed-point: once |size - ewma| < alpha_den the update rounds to 0, so
        // ewma settles within < alpha_den bytes of the true value — negligible
        // at KiB buffer granularity.
        let a_n = self.cfg.alpha_num as usize;
        let a_d = self.cfg.alpha_den as usize;
        if size >= self.ewma {
            self.ewma += (size - self.ewma) * a_n / a_d;
        } else {
            self.ewma -= (self.ewma - size) * a_n / a_d;
        }
        self.reconcile();
    }

    /// A parser hint that at least `need` more bytes are coming: bump the target
    /// immediately (proactive), without waiting for the EWMA to catch up.
    pub fn hint(&mut self, need: usize) {
        let want = need.clamp(self.cfg.min, self.cfg.max);
        if want > self.target {
            self.target = want;
        }
    }

    /// Current target buffer size in bytes, clamped to [min, max].
    pub fn target(&self) -> usize {
        self.target
    }

    fn reconcile(&mut self) {
        let ewma = self.ewma.clamp(self.cfg.min, self.cfg.max);
        if ewma > self.target {
            // Upshift immediately toward demand.
            self.target = ewma;
        } else {
            // Downshift only past the hysteresis band.
            let band =
                self.target * self.cfg.downshift_num as usize / self.cfg.downshift_den as usize;
            if ewma < band {
                self.target = ewma;
            }
        }
    }
}

/// Index of the smallest class whose buffer size is >= `target`, clamped to the
/// largest class. `classes` must be ascending and non-empty.
pub(crate) fn class_index_for(classes: &[usize], target: usize) -> usize {
    classes
        .iter()
        .position(|&c| c >= target)
        .unwrap_or(classes.len() - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SizingPolicy {
        // min 4 KiB, max 512 KiB, alpha = 0.25, downshift band = 0.5
        SizingPolicy::new(SizingConfig {
            min: 4 * 1024,
            max: 512 * 1024,
            alpha_num: 1,
            alpha_den: 4,
            downshift_num: 1,
            downshift_den: 2,
        })
    }

    #[test]
    fn starts_at_min() {
        assert_eq!(policy().target(), 4 * 1024);
    }

    #[test]
    fn sustained_large_raises_target() {
        let mut p = policy();
        for _ in 0..20 {
            p.observe(200 * 1024);
        }
        assert!(p.target() >= 128 * 1024, "target was {}", p.target());
    }

    #[test]
    fn hint_bumps_immediately() {
        let mut p = policy();
        p.hint(300 * 1024);
        assert!(p.target() >= 300 * 1024);
    }

    #[test]
    fn target_clamped_to_max() {
        let mut p = policy();
        p.hint(10 * 1024 * 1024);
        assert_eq!(p.target(), 512 * 1024);
    }

    #[test]
    fn brief_dip_does_not_downshift() {
        let mut p = policy();
        for _ in 0..20 {
            p.observe(200 * 1024);
        }
        let high = p.target();
        p.observe(1024); // one small sample
        assert_eq!(p.target(), high, "single dip should not downshift");
    }

    #[test]
    fn sustained_dip_downshifts() {
        let mut p = policy();
        for _ in 0..20 {
            p.observe(200 * 1024);
        }
        for _ in 0..40 {
            p.observe(1024);
        }
        assert!(p.target() < 128 * 1024, "target was {}", p.target());
    }

    #[test]
    fn class_for_picks_smallest_class_ge_target() {
        // classes: 4K, 64K, 512K
        let classes = [4 * 1024, 64 * 1024, 512 * 1024];
        assert_eq!(class_index_for(&classes, 3 * 1024), 0);
        assert_eq!(class_index_for(&classes, 4 * 1024), 0);
        assert_eq!(class_index_for(&classes, 5 * 1024), 1);
        assert_eq!(class_index_for(&classes, 600 * 1024), 2); // clamps to largest
    }
}
