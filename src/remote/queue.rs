//! Durability primitives for the remote ingest agent.
//!
//! The old publisher was fire-and-forget: a single latest-snapshot slot,
//! POSTed every 15s, dropped on any error. At fleet scale that silently gaps
//! telemetry on every network blip. These two small pieces fix that:
//!
//! - [`SnapshotQueue`] — a bounded, drop-oldest buffer. The sender *peeks* a
//!   batch and only *removes* it once the backend ACKs, so a transient outage
//!   never loses data up to `cap`. Overflow drops the oldest and counts it, so
//!   the backend can surface "agent shedding load" instead of a silent gap.
//! - [`Backoff`] — exponential backoff with jitter for retry pacing, so a
//!   recovering backend doesn't get a thundering herd from a reconnecting fleet.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Bounded queue of pending ingest snapshots with at-least-once delivery
/// semantics: items stay in the queue until explicitly removed after an ACK.
pub struct SnapshotQueue {
    inner: Mutex<VecDeque<serde_json::Value>>,
    cap: usize,
    // u32, not u64: this counts overflow drops of whole snapshots (one push
    // per agent tick, seconds apart), so wrapping would take centuries even
    // under sustained overload. armv5te (old Kirkwood NAS boxes) has no
    // native 64-bit atomics.
    dropped: AtomicU32,
}

impl SnapshotQueue {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(cap.min(1024))),
            cap: cap.max(1),
            dropped: AtomicU32::new(0),
        }
    }

    /// Enqueue a snapshot. On overflow, drop the *oldest* (it's the stalest and
    /// least useful) and bump the dropped counter.
    pub fn push(&self, snapshot: serde_json::Value) {
        let mut q = self.lock();
        while q.len() >= self.cap {
            q.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        q.push_back(snapshot);
    }

    /// Clone up to `max` of the oldest snapshots for sending, without removing
    /// them. They are only removed via [`remove`](Self::remove) after an ACK.
    pub fn peek_batch(&self, max: usize) -> Vec<serde_json::Value> {
        let q = self.lock();
        q.iter().take(max).cloned().collect()
    }

    /// Remove the `n` oldest snapshots (call after the backend ACKs a batch).
    pub fn remove(&self, n: usize) {
        let mut q = self.lock();
        for _ in 0..n.min(q.len()) {
            q.pop_front();
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total snapshots dropped to overflow since start. Reported in the wire
    /// envelope so the backend can flag a struggling agent.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed) as u64
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<serde_json::Value>> {
        // A poisoned lock here means a prior holder panicked mid-mutation. The
        // queue invariants are simple (a deque), so recovering the guard and
        // continuing is strictly better than killing the only sender thread.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Exponential backoff with full jitter, bounded by `max`.
///
/// `delay()` is deterministic given attempt + seed; the seed is folded in so a
/// reconnecting fleet spreads its retries instead of synchronizing. There is no
/// RNG dependency — the caller passes a per-attempt entropy source (e.g. the
/// low bits of a monotonic clock), keeping this unit-testable and dep-free.
pub struct Backoff {
    base: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            attempt: 0,
        }
    }

    /// Reset after a successful send.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Record a failure and return the delay to wait before the next attempt.
    /// `entropy` provides jitter (full jitter: uniform in `[0, capped]`). It
    /// must be uniform over all of `u64`: it picks its point in proportion,
    /// so 0 waits nothing and `u64::MAX` waits the whole ceiling.
    pub fn fail(&mut self, entropy: u64) -> Duration {
        let capped = self.capped_ceiling();
        self.attempt = self.attempt.saturating_add(1);
        // Scaled rather than reduced modulo the ceiling: entropy drawn from a
        // narrower range than the ceiling's, such as the sub-second
        // nanoseconds this once took, would keep every delay inside it.
        let ceil_nanos = capped.as_nanos().min(u64::MAX as u128);
        let jittered = (entropy as u128 * (ceil_nanos + 1)) >> 64;
        Duration::from_nanos(jittered as u64)
    }

    /// The current (un-jittered) backoff ceiling for the next attempt.
    fn capped_ceiling(&self) -> Duration {
        let factor = 1u64.checked_shl(self.attempt.min(32)).unwrap_or(u64::MAX);
        let scaled = self.base.saturating_mul(factor.min(u32::MAX as u64) as u32);
        scaled.min(self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snap(i: u64) -> serde_json::Value {
        json!({ "seq": i })
    }

    #[test]
    fn push_within_cap_keeps_everything() {
        let q = SnapshotQueue::new(4);
        for i in 0..3 {
            q.push(snap(i));
        }
        assert_eq!(q.len(), 3);
        assert_eq!(q.dropped(), 0);
    }

    #[test]
    fn overflow_drops_oldest_and_counts() {
        let q = SnapshotQueue::new(3);
        for i in 0..5 {
            q.push(snap(i));
        }
        assert_eq!(q.len(), 3);
        assert_eq!(q.dropped(), 2);
        // The three newest survive (oldest two evicted).
        let batch = q.peek_batch(10);
        assert_eq!(batch[0]["seq"], 2);
        assert_eq!(batch[2]["seq"], 4);
    }

    #[test]
    fn peek_does_not_remove() {
        let q = SnapshotQueue::new(8);
        q.push(snap(1));
        q.push(snap(2));
        let a = q.peek_batch(8);
        let b = q.peek_batch(8);
        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 2); // still there — peek is non-destructive
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn ack_gated_remove_advances_queue() {
        let q = SnapshotQueue::new(8);
        for i in 0..5 {
            q.push(snap(i));
        }
        let batch = q.peek_batch(2);
        assert_eq!(batch.len(), 2);
        // Simulate ACK of the 2 sent.
        q.remove(2);
        assert_eq!(q.len(), 3);
        assert_eq!(q.peek_batch(1)[0]["seq"], 2);
    }

    #[test]
    fn remove_more_than_present_is_safe() {
        let q = SnapshotQueue::new(8);
        q.push(snap(1));
        q.remove(10);
        assert!(q.is_empty());
    }

    #[test]
    fn batch_max_caps_take() {
        let q = SnapshotQueue::new(100);
        for i in 0..50 {
            q.push(snap(i));
        }
        assert_eq!(q.peek_batch(10).len(), 10);
    }

    #[test]
    fn backoff_grows_then_caps() {
        let mut b = Backoff::new(Duration::from_millis(250), Duration::from_secs(60));
        // With max entropy, jittered delay approaches the ceiling; ceilings grow.
        let huge = u64::MAX;
        let d0 = b.fail(huge);
        let d1 = b.fail(huge);
        let d2 = b.fail(huge);
        assert!(d1 >= d0, "ceiling should not shrink: {d0:?} -> {d1:?}");
        assert!(d2 >= d1, "ceiling should not shrink: {d1:?} -> {d2:?}");
        // Drive many failures; never exceed max.
        for _ in 0..40 {
            let d = b.fail(huge);
            assert!(d <= Duration::from_secs(60));
        }
    }

    /// Review R5: every delay up to the ceiling is reachable. Full entropy
    /// waits each ceiling in turn, doubling from the base to the cap, no
    /// entropy waits nothing, and half waits half.
    #[test]
    fn delays_reach_each_ceiling_up_to_the_cap() {
        let ms = Duration::from_millis;
        let mut b = Backoff::new(ms(500), Duration::from_secs(60));
        let full: Vec<Duration> = (0..10).map(|_| b.fail(u64::MAX)).collect();
        assert_eq!(
            full,
            [500, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000, 60_000].map(ms)
        );

        let mut b = Backoff::new(ms(500), Duration::from_secs(60));
        assert_eq!(b.fail(0), Duration::ZERO);
        assert_eq!(b.fail(1 << 63), ms(500), "half of the second ceiling, 1 s");
        b.reset();
        assert_eq!(
            b.fail(u64::MAX),
            ms(500),
            "a success starts again from the base"
        );
    }

    #[test]
    fn backoff_jitter_is_bounded_by_ceiling() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(10));
        // First failure ceiling is `base` (2^0 * base). Jitter must stay within.
        let d = b.fail(12345);
        assert!(d < Duration::from_millis(100));
    }

    #[test]
    fn reset_shrinks_ceiling_back_to_base() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(60));
        // Climb several attempts so the ceiling is well above base.
        for _ in 0..6 {
            b.fail(u64::MAX);
        }
        let high = b.capped_ceiling();
        assert!(high > Duration::from_millis(100));
        // After a successful send, the next failure starts from base again.
        b.reset();
        assert_eq!(b.capped_ceiling(), Duration::from_millis(100));
    }
}
