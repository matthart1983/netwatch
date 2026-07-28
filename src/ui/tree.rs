//! Shared machinery for the grouped-tree tables (Egress, Connections).
//!
//! Several screens hold the same shape of data — a set of rows that all carry
//! a process name, or a host — and rendering that as a flat table spends a
//! large fraction of the widest column repeating the string above it. The
//! Egress tab replaced its flat table with a tree (one parent row per group,
//! carrying a rollup, with foldable children) and this module is that pattern
//! pulled out so a second screen doesn't reimplement it.
//!
//! Deliberately *not* shared: rendering. The two screens draw very
//! differently — Egress builds a `ratatui::Table`, Connections paints each row
//! at explicit column offsets — and forcing one renderer on both would be a
//! worse fit than the duplication it removes. What is shared is the part that
//! was actually error-prone: grouping, fold state, flattening to a numbered
//! row list, and mapping a screen position back to a row. That last one is
//! where issue #28 lived (clicks resolved against the *previous selection*
//! rather than the visible window), and it is worth having exactly once.

use std::collections::HashSet;

/// A group of children sharing a key, plus whatever summary the screen wants
/// on the parent row.
///
/// `rollup` is computed by the caller rather than here: "sum the bytes" means
/// something different on every screen, and a trait to abstract it would be
/// more machinery than the two implementations justify.
pub struct Group<R, C> {
    /// The value rows were grouped by — a process name, a remote host. Also
    /// the fold-state identity, so it must be stable frame to frame.
    pub key: String,
    pub rollup: R,
    pub children: Vec<C>,
}

/// One line of a rendered tree: a group header, or one of its children.
pub enum Row<'a, R, C> {
    Parent {
        group: &'a Group<R, C>,
        collapsed: bool,
    },
    Child {
        group: &'a Group<R, C>,
        item: &'a C,
    },
}

impl<R, C> Row<'_, R, C> {
    /// The group this row belongs to — the same answer for a parent and for
    /// any of its children, which is what makes "fold the thing under the
    /// cursor" work from a child row.
    pub fn key(&self) -> &str {
        match self {
            Row::Parent { group, .. } | Row::Child { group, .. } => &group.key,
        }
    }

    pub fn is_parent(&self) -> bool {
        matches!(self, Row::Parent { .. })
    }
}

/// Bucket items by key, preserving first-seen order within each group.
///
/// Order of the groups themselves is left to the caller: every screen wants
/// to sort them by its own rollup (volume, risk, rate), and sorting here
/// would only be overwritten.
pub fn group_by<T, K>(items: impl IntoIterator<Item = T>, key: K) -> Vec<(String, Vec<T>)>
where
    K: Fn(&T) -> String,
{
    let mut order: Vec<String> = Vec::new();
    let mut buckets: std::collections::HashMap<String, Vec<T>> = std::collections::HashMap::new();
    for item in items {
        let k = key(&item);
        buckets.entry(k.clone()).or_insert_with(|| {
            order.push(k.clone());
            Vec::new()
        });
        buckets.get_mut(&k).expect("just inserted").push(item);
    }
    order
        .into_iter()
        .map(|k| {
            let v = buckets.remove(&k).unwrap_or_default();
            (k, v)
        })
        .collect()
}

/// Flatten groups into the visible row list, honouring fold state.
///
/// This is the single definition of "what is on screen, in order". Both the
/// renderer and the input handlers go through it, so a click, an arrow key
/// and a drawn row can never disagree about what row 7 is.
pub fn flatten<'a, R, C>(groups: &'a [Group<R, C>], fold: &FoldState) -> Vec<Row<'a, R, C>> {
    let mut rows = Vec::new();
    for group in groups {
        let is_collapsed = fold.is_collapsed(&group.key);
        rows.push(Row::Parent {
            group,
            collapsed: is_collapsed,
        });
        if !is_collapsed {
            for item in &group.children {
                rows.push(Row::Child { group, item });
            }
        }
    }
    rows
}

/// Which groups are folded.
///
/// Stored as a default plus the keys that differ from it, rather than a set of
/// collapsed names. The distinction matters because groups appear and vanish
/// while you are looking at the screen: with a plain collapsed-set, a process
/// that starts talking *after* you collapsed everything would arrive expanded,
/// and "fold all" would quietly come undone one row at a time. Here a new
/// group inherits the default, so the screen stays as the user arranged it.
///
/// It also makes fold-all and expand-all exact rather than best-effort — they
/// set the default and drop the exceptions, so they cannot leave a straggler.
#[derive(Debug, Clone, Default)]
pub struct FoldState {
    /// What a group does when nothing specific has been said about it.
    default_collapsed: bool,
    /// Keys whose state is the opposite of `default_collapsed`.
    exceptions: HashSet<String>,
}

impl FoldState {
    /// A fold state where groups start collapsed (or not), per config.
    pub fn new(default_collapsed: bool) -> Self {
        Self {
            default_collapsed,
            exceptions: HashSet::new(),
        }
    }

    pub fn is_collapsed(&self, key: &str) -> bool {
        self.default_collapsed != self.exceptions.contains(key)
    }

    /// Toggle one group. Returns true if it is now collapsed.
    pub fn toggle(&mut self, key: &str) -> bool {
        if !self.exceptions.remove(key) {
            self.exceptions.insert(key.to_string());
        }
        self.is_collapsed(key)
    }

    pub fn collapse_all(&mut self) {
        self.default_collapsed = true;
        self.exceptions.clear();
    }

    pub fn expand_all(&mut self) {
        self.default_collapsed = false;
        self.exceptions.clear();
    }

    /// Whether every group is currently collapsed — what a single fold-all
    /// key needs in order to decide which way to go.
    pub fn all_collapsed(&self) -> bool {
        self.default_collapsed && self.exceptions.is_empty()
    }

    /// Collapse everything if anything is open, otherwise open everything.
    /// Returns true if the result is collapsed.
    pub fn toggle_all(&mut self) -> bool {
        if self.all_collapsed() {
            self.expand_all();
            false
        } else {
            self.collapse_all();
            true
        }
    }
}

/// First visible row index given the selection, so the cursor stays on screen.
///
/// Keeps the selection centred once it leaves the first page, rather than
/// scrolling one row at a time from the top.
pub fn window_top(selected: usize, total: usize, visible: usize) -> usize {
    if selected < visible {
        return 0;
    }
    selected
        .saturating_sub(visible / 2)
        .min(total.saturating_sub(visible))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn groups() -> Vec<Group<usize, &'static str>> {
        vec![
            Group {
                key: "curl".into(),
                rollup: 2,
                children: vec!["a", "b"],
            },
            Group {
                key: "gh".into(),
                rollup: 1,
                children: vec!["c"],
            },
        ]
    }

    #[test]
    fn flatten_emits_a_parent_then_its_children() {
        let g = groups();
        let rows = flatten(&g, &FoldState::new(false));
        assert_eq!(rows.len(), 5);
        assert!(rows[0].is_parent());
        assert_eq!(rows[0].key(), "curl");
        assert!(!rows[1].is_parent());
        assert_eq!(rows[1].key(), "curl", "a child reports its parent's key");
        assert!(rows[3].is_parent());
        assert_eq!(rows[3].key(), "gh");
    }

    /// A collapsed group keeps its header — folding hides detail, it never
    /// hides the existence of the thing.
    #[test]
    fn collapsing_hides_children_but_never_the_parent() {
        let g = groups();
        let mut fold = FoldState::new(false);
        fold.toggle("curl");
        let rows = flatten(&g, &fold);
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| r.is_parent() || r.key() == "gh"));
        assert!(rows[0].is_parent() && rows[0].key() == "curl");
    }

    #[test]
    fn toggle_round_trips() {
        let mut fold = FoldState::new(false);
        assert!(fold.toggle("curl"));
        assert!(fold.is_collapsed("curl"));
        assert!(!fold.toggle("curl"));
        assert!(!fold.is_collapsed("curl"));
    }

    /// Starting collapsed must mean *every* group, including ones that did
    /// not exist yet. A collapsed-set model gets this wrong: a process that
    /// starts talking after you folded everything arrives expanded, and the
    /// screen you arranged unpicks itself one row at a time.
    #[test]
    fn a_group_first_seen_later_inherits_the_default() {
        let fold = FoldState::new(true);
        assert!(fold.is_collapsed("never-seen-before"));
        let open = FoldState::new(false);
        assert!(!open.is_collapsed("never-seen-before"));
    }

    /// Toggling one group under a collapsed default expands just that one,
    /// and leaves everything else — present and future — folded.
    #[test]
    fn an_exception_does_not_disturb_the_default() {
        let mut fold = FoldState::new(true);
        assert!(!fold.toggle("curl"), "toggling a collapsed group opens it");
        assert!(!fold.is_collapsed("curl"));
        assert!(fold.is_collapsed("gh"));
        assert!(fold.is_collapsed("appears-later"));
        assert!(!fold.all_collapsed(), "one group is open");
    }

    /// Fold-all and expand-all must be exact, not best-effort — they drop the
    /// exceptions rather than trying to enumerate what is currently open.
    #[test]
    fn fold_all_leaves_no_stragglers() {
        let mut fold = FoldState::new(false);
        fold.toggle("curl");
        fold.toggle("gh");
        fold.collapse_all();
        assert!(fold.all_collapsed());
        for k in ["curl", "gh", "brand-new"] {
            assert!(fold.is_collapsed(k), "{k} should be folded");
        }

        fold.expand_all();
        for k in ["curl", "gh", "brand-new"] {
            assert!(!fold.is_collapsed(k), "{k} should be open");
        }
    }

    #[test]
    fn toggle_all_flips_between_fully_folded_and_fully_open() {
        let mut fold = FoldState::new(false);
        assert!(fold.toggle_all(), "anything open → fold everything");
        assert!(fold.all_collapsed());
        assert!(!fold.toggle_all(), "all folded → open everything");
        assert!(!fold.is_collapsed("curl"));

        // A single open group is still "not all collapsed", so the next
        // toggle folds rather than expanding a screen that is mostly folded.
        fold.collapse_all();
        fold.toggle("curl");
        assert!(fold.toggle_all());
        assert!(fold.all_collapsed());
    }

    #[test]
    fn group_by_preserves_first_seen_order_and_membership() {
        let items = vec![("a", 1), ("b", 2), ("a", 3)];
        let g = group_by(items, |(k, _)| k.to_string());
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].0, "a", "first key seen comes first");
        assert_eq!(g[0].1, vec![("a", 1), ("a", 3)]);
        assert_eq!(g[1].0, "b");
    }

    /// The window must never scroll past the end, or the last page renders
    /// blank rows below the final item.
    #[test]
    fn window_top_clamps_to_the_last_page() {
        assert_eq!(window_top(0, 100, 10), 0);
        assert_eq!(window_top(5, 100, 10), 0, "first page never scrolls");
        assert_eq!(window_top(50, 100, 10), 45, "selection stays centred");
        assert_eq!(window_top(99, 100, 10), 90, "clamped to the last page");
        assert_eq!(window_top(5, 3, 10), 0, "fewer items than the window");
    }
}
