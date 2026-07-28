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
pub fn flatten<'a, R, C>(
    groups: &'a [Group<R, C>],
    collapsed: &HashSet<String>,
) -> Vec<Row<'a, R, C>> {
    let mut rows = Vec::new();
    for group in groups {
        let is_collapsed = collapsed.contains(&group.key);
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

/// Toggle a group's fold state. Returns true if it is now collapsed.
pub fn toggle(collapsed: &mut HashSet<String>, key: &str) -> bool {
    if collapsed.remove(key) {
        false
    } else {
        collapsed.insert(key.to_string());
        true
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
        let rows = flatten(&g, &HashSet::new());
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
        let mut collapsed = HashSet::new();
        collapsed.insert("curl".to_string());
        let rows = flatten(&g, &collapsed);
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| r.is_parent() || r.key() == "gh"));
        assert!(rows[0].is_parent() && rows[0].key() == "curl");
    }

    #[test]
    fn toggle_round_trips() {
        let mut collapsed = HashSet::new();
        assert!(toggle(&mut collapsed, "curl"));
        assert!(collapsed.contains("curl"));
        assert!(!toggle(&mut collapsed, "curl"));
        assert!(collapsed.is_empty());
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
