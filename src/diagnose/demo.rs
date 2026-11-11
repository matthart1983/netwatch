//! `--demo`: the Diagnose tab driven by the recorded scenario instead of the
//! live network.
//!
//! ## Why this exists
//!
//! Diagnose only has something to say when something is wrong, and it needs
//! thirty minutes of baseline before it will say it. That is correct
//! behaviour and it makes the feature impossible to show: a screenshot of a
//! healthy laptop is an empty list, and nobody is going to break their own DNS
//! to evaluate a tool. So the scenario in [`super::fixture`] is replayed
//! through the real engine, the real rules and the real UI — only the
//! observations are recorded rather than measured.
//!
//! ## The rules this mode plays by
//!
//! 1. **It says so, always.** [`DemoDriver::banner`] is rendered in the engine
//!    strip and cannot be turned off. A demo that can be mistaken for live
//!    measurement is worse than no demo.
//! 2. **It touches nothing.** Remediations are simulated, never applied. The
//!    resolver on the host running the demo is not written to, and the
//!    journal is not involved.
//! 3. **It does not cheat the engine.** Applying the fix does not mark the
//!    issue resolved — it changes what the resolver *observes*, and the same
//!    verify condition that governs a live issue (`dns.rtt_p50` under 0.8 of
//!    the line it opened on, which reads `< 5ms` here, held for 60s) is what
//!    closes it. The demo can show the loop closing because the loop actually
//!    closes.

use std::sync::Arc;

use super::baseline::BaselineStore;
use super::engine::{Clock, Engine, FixedClock};
use super::fixture;
use super::issue::{Action, Applied};

/// Scenario seconds advanced per UI tick.
///
/// The scenario runs 440 seconds and netwatch ticks once a second, so at 1×
/// a viewer would wait four minutes for the DNS onset. At 6× the whole arc —
/// reroute, resolver, socket, fix, verify, close — fits inside a two-minute
/// recording while every duration the screen quotes stays the scenario's own.
pub const DEFAULT_SPEED: u64 = 6;

/// Where the replay stops, in scenario seconds.
///
/// Past [`fixture::SCENARIO_SECS`] (the window the exported report covers) on
/// purpose. The resolver rule verifies on 60 seconds of health, so a replay
/// that stopped at the report's end would run out before it could show the
/// issue closing — the one beat that proves the loop closes at all. The
/// scenario is steady after its last onset, so the extra minutes are simply
/// the same healthy readings continuing.
pub const DEMO_END: u64 = 560;

/// Where the replay starts, in scenario seconds.
///
/// Not zero: the first four minutes are a healthy network, which is a true
/// part of the story and a dull thing to watch. 236 opens a few seconds
/// before the resolver degrades at 250, so a viewer sees the transition from
/// quiet to a finding rather than arriving after it.
pub const DEFAULT_START: u64 = 236;

pub struct DemoDriver {
    clock: Arc<FixedClock>,
    /// Scenario position, in seconds from `fixture::WINDOW_START`.
    t: u64,
    speed: u64,
    /// Set once the operator applies the resolver remediation. From then on
    /// the scenario reports the alternate resolver's real latency.
    resolver_fixed: bool,
    /// Scenario second at which the fix was applied, for the banner.
    fixed_at: Option<u64>,
}

impl DemoDriver {
    pub fn new() -> (Self, Engine, BaselineStore) {
        let clock = Arc::new(FixedClock::at(fixture::WINDOW_START));
        clock.advance_secs(DEFAULT_START as i64);
        let engine = Engine::new(Box::new(ClockRef(clock.clone())));
        let driver = Self {
            clock,
            t: DEFAULT_START,
            speed: DEFAULT_SPEED,
            resolver_fixed: false,
            fixed_at: None,
        };
        (driver, engine, fixture::baselines())
    }

    /// Advance the scenario and feed the engine. Returns when the scenario has
    /// run out, after which the clock stops and the screen holds its last
    /// state rather than looping — a demo that silently restarts makes a
    /// viewer distrust the timestamps.
    pub fn tick(&mut self, engine: &mut Engine, base: &BaselineStore) {
        if self.finished() {
            return;
        }
        for _ in 0..self.speed {
            if self.finished() {
                break;
            }
            self.t += 1;
            self.clock.advance_secs(1);
            engine.observe(
                &fixture::observations_with(self.t, self.resolver_fixed),
                base,
            );
        }
    }

    pub fn finished(&self) -> bool {
        self.t >= DEMO_END
    }

    /// Simulate a remediation. Returns the [`Applied`] record to attach to the
    /// step, exactly as the live path would — but nothing on this host is
    /// written to.
    ///
    /// Only `SetResolver` changes the scenario; anything else records honestly
    /// that the demo does not model it, rather than claiming a fix it cannot
    /// show the effect of.
    pub fn apply(&mut self, action: &Action) -> Applied {
        match action {
            Action::SetResolver { addr } => {
                self.resolver_fixed = true;
                self.fixed_at = Some(self.t);
                Applied::Yes {
                    at: super::engine::format_ts(self.clock.now()),
                    before: fixture::RESOLVER.to_string(),
                    after: addr.clone(),
                }
            }
            _ => Applied::No {
                reason: "the demo scenario does not model this step".into(),
            },
        }
    }

    /// The line the Diagnose tab shows instead of the live network label.
    /// Names the scenario, the position within it, and the speed, so nothing
    /// on screen can be mistaken for a measurement of the host.
    pub fn banner(&self) -> String {
        let mut s = format!(
            "DEMO — replaying a recorded incident at {}× · {}s of {}s",
            self.speed,
            self.t.min(DEMO_END),
            DEMO_END
        );
        if self.finished() {
            s.push_str(" · ended");
        } else if let Some(at) = self.fixed_at {
            s.push_str(&format!(
                " · resolver switch simulated at {at}s, waiting on verify"
            ));
        }
        s
    }

    pub fn resolver_fixed(&self) -> bool {
        self.resolver_fixed
    }
}

struct ClockRef(Arc<FixedClock>);

impl Clock for ClockRef {
    fn now(&self) -> chrono::DateTime<chrono::Local> {
        self.0.now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_replay_opens_the_resolver_issue_within_a_few_ticks() {
        let (mut d, mut e, base) = DemoDriver::new();
        for _ in 0..6 {
            d.tick(&mut e, &base);
        }
        assert!(
            e.primary().iter().any(|i| i.rule == "dns.slow_resolver"),
            "the replay must reach the incident quickly enough to record"
        );
    }

    #[test]
    fn applying_the_fix_closes_the_issue_through_the_normal_verify_path() {
        let (mut d, mut e, base) = DemoDriver::new();
        for _ in 0..6 {
            d.tick(&mut e, &base);
        }
        let issue = e
            .primary()
            .iter()
            .find(|i| i.rule == "dns.slow_resolver")
            .map(|i| i.id.clone())
            .expect("resolver issue open");

        let applied = d.apply(&Action::SetResolver {
            addr: fixture::ALT_RESOLVER.into(),
        });
        assert!(matches!(applied, Applied::Yes { .. }));
        e.record_applied(&issue, '1', applied);

        // Not instantly closed — the verify window still has to elapse.
        d.tick(&mut e, &base);
        assert!(e.get(&issue).unwrap().state.is_open());

        for _ in 0..20 {
            d.tick(&mut e, &base);
        }
        assert!(
            !e.get(&issue).unwrap().state.is_open(),
            "the demo closes the loop through verify, not by fiat"
        );
    }

    #[test]
    fn a_step_the_scenario_cannot_model_says_so() {
        let (mut d, _, _) = DemoDriver::new();
        let applied = d.apply(&Action::Watch { secs: 30 });
        assert!(matches!(applied, Applied::No { .. }));
        assert!(!d.resolver_fixed());
    }

    #[test]
    fn the_banner_always_identifies_itself_as_a_demo() {
        let (mut d, mut e, base) = DemoDriver::new();
        assert!(d.banner().starts_with("DEMO"));
        for _ in 0..200 {
            d.tick(&mut e, &base);
        }
        assert!(d.banner().starts_with("DEMO"));
        assert!(d.finished());
        assert!(d.banner().contains("ended"));
    }

    #[test]
    fn the_replay_outlasts_the_verify_window_after_a_late_fix() {
        // The tape applies the fix well into the run. If the replay ended at
        // the report window, the issue could never be seen closing.
        let (mut d, mut e, base) = DemoDriver::new();
        while d.t < 380 {
            d.tick(&mut e, &base);
        }
        let issue = e
            .primary()
            .iter()
            .find(|i| i.rule == "dns.slow_resolver")
            .map(|i| i.id.clone())
            .expect("resolver issue still open this late in the run");

        let applied = d.apply(&Action::SetResolver {
            addr: fixture::ALT_RESOLVER.into(),
        });
        e.record_applied(&issue, '1', applied);

        while !d.finished() {
            d.tick(&mut e, &base);
        }
        assert!(
            !e.get(&issue).unwrap().state.is_open(),
            "the replay must outlast the 60s verify window, or the demo \
             stops before its payoff"
        );
    }

    #[test]
    fn the_replay_stops_rather_than_looping() {
        let (mut d, mut e, base) = DemoDriver::new();
        for _ in 0..500 {
            d.tick(&mut e, &base);
        }
        let first = d.banner();
        for _ in 0..50 {
            d.tick(&mut e, &base);
        }
        assert_eq!(first, d.banner(), "a finished scenario must hold still");
    }
}
