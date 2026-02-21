//! Ketama consistent hash ring.
//!
//! Provides consistent hashing compatible with libmemcached/twemproxy.
//! Adding or removing a server remaps only ~1/N of keys instead of all keys.

mod md5;

use md5::md5;

/// Immutable ketama consistent hash ring.
///
/// The ring maps keys to shard indices using MD5-based virtual nodes,
/// compatible with the libmemcached/twemproxy ketama algorithm.
#[derive(Clone, Debug)]
pub struct Ring {
    /// Sorted (hash_point, shard_index) pairs.
    points: Box<[(u32, u16)]>,
    node_count: u16,
}

impl Ring {
    /// Build a ring from server identity strings with equal weight (160 virtual nodes each).
    pub fn build(servers: &[&str]) -> Self {
        let mut builder = RingBuilder::new();
        for &server in servers {
            builder = builder.node(server, 1);
        }
        builder.build()
    }

    /// Route a key to a shard index in `0..node_count`.
    #[inline]
    pub fn route(&self, key: &[u8]) -> usize {
        if self.node_count <= 1 {
            return 0;
        }
        let hash = key_hash(key);
        let idx = self.points.partition_point(|&(point, _)| point < hash);
        let idx = if idx == self.points.len() { 0 } else { idx };
        self.points[idx].1 as usize
    }

    /// Number of logical nodes (servers) in the ring.
    pub fn node_count(&self) -> usize {
        self.node_count as usize
    }

    /// Total number of virtual node points on the ring.
    pub fn point_count(&self) -> usize {
        self.points.len()
    }
}

/// Builder for constructing a [`Ring`] with weighted nodes.
pub struct RingBuilder {
    nodes: Vec<(String, u32)>,
}

impl RingBuilder {
    pub fn new() -> Self {
        RingBuilder { nodes: Vec::new() }
    }

    /// Add a node with the given identity string and weight.
    ///
    /// Weight 1 produces 160 virtual nodes (the standard ketama default).
    /// Weight W produces `160 * W` virtual nodes.
    pub fn node(mut self, identity: &str, weight: u32) -> Self {
        self.nodes.push((identity.to_owned(), weight));
        self
    }

    /// Build the immutable ring.
    ///
    /// # Panics
    ///
    /// Panics if no nodes were added.
    pub fn build(self) -> Ring {
        assert!(!self.nodes.is_empty(), "Ring must have at least one node");

        let mut points = Vec::new();

        for (shard_idx, (identity, weight)) in self.nodes.iter().enumerate() {
            let num_points = 160 * (*weight as usize);
            // Each MD5 digest yields 4 hash points
            let num_hashes = num_points / 4;

            for i in 0..num_hashes {
                let key = format!("{identity}-{i}");
                let digest = md5(key.as_bytes());

                for j in 0..4 {
                    let off = j * 4;
                    let hash = u32::from_le_bytes([
                        digest[off],
                        digest[off + 1],
                        digest[off + 2],
                        digest[off + 3],
                    ]);
                    points.push((hash, shard_idx as u16));
                }
            }
        }

        points.sort_unstable_by_key(|&(hash, _)| hash);

        Ring {
            points: points.into_boxed_slice(),
            node_count: self.nodes.len() as u16,
        }
    }
}

impl Default for RingBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash a key to a u32 using MD5 (first 4 bytes, little-endian).
#[inline]
fn key_hash(key: &[u8]) -> u32 {
    let digest = md5(key);
    u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_node_always_zero() {
        let ring = Ring::build(&["server-0:11211"]);
        assert_eq!(ring.route(b"any-key"), 0);
        assert_eq!(ring.route(b""), 0);
        assert_eq!(ring.route(b"another-key"), 0);
    }

    #[test]
    fn deterministic_routing() {
        let ring = Ring::build(&["s0:11211", "s1:11211", "s2:11211"]);
        let a = ring.route(b"test-key");
        let b = ring.route(b"test-key");
        assert_eq!(a, b);
    }

    #[test]
    fn roughly_uniform_distribution() {
        let ring = Ring::build(&["s0:11211", "s1:11211", "s2:11211"]);
        let mut counts = [0u32; 3];
        for i in 0..10_000u32 {
            let key = format!("key-{i}");
            let shard = ring.route(key.as_bytes());
            counts[shard] += 1;
        }
        // Each of 3 servers should get 25-45% of 10k keys
        for (i, &count) in counts.iter().enumerate() {
            assert!(
                (2500..=4500).contains(&count),
                "server {i} got {count} keys, expected 2500-4500: {counts:?}"
            );
        }
    }

    #[test]
    fn weighted_distribution() {
        let ring = RingBuilder::new()
            .node("s0:11211", 1)
            .node("s1:11211", 2)
            .build();
        let mut counts = [0u32; 2];
        for i in 0..10_000u32 {
            let key = format!("key-{i}");
            counts[ring.route(key.as_bytes())] += 1;
        }
        // s1 (weight 2) should get roughly 2x traffic of s0 (weight 1)
        let ratio = counts[1] as f64 / counts[0] as f64;
        assert!(
            (1.5..2.5).contains(&ratio),
            "weight ratio {ratio:.2}, counts: {counts:?}"
        );
    }

    #[test]
    fn minimal_remapping_on_node_add() {
        let ring3 = Ring::build(&["s0:11211", "s1:11211", "s2:11211"]);
        let ring4 = Ring::build(&["s0:11211", "s1:11211", "s2:11211", "s3:11211"]);

        let total = 10_000u32;
        let mut remapped = 0u32;
        for i in 0..total {
            let key = format!("key-{i}");
            let kb = key.as_bytes();
            if ring3.route(kb) != ring4.route(kb) {
                remapped += 1;
            }
        }
        // Ideal: 25% remapped (1/4). Allow up to 40%.
        let pct = remapped as f64 / total as f64;
        assert!(
            pct < 0.40,
            "remapped {pct:.1}% of keys (expected <40%): {remapped}/{total}"
        );
    }

    #[test]
    fn point_count() {
        let ring = Ring::build(&["s0:11211", "s1:11211"]);
        assert_eq!(ring.point_count(), 320); // 2 * 160
        assert_eq!(ring.node_count(), 2);
    }

    #[test]
    fn weighted_point_count() {
        let ring = RingBuilder::new()
            .node("s0:11211", 1)
            .node("s1:11211", 3)
            .build();
        // s0: 160 points, s1: 480 points = 640 total
        assert_eq!(ring.point_count(), 640);
    }

    #[test]
    #[should_panic(expected = "at least one node")]
    fn empty_ring_panics() {
        RingBuilder::new().build();
    }
}
