//! Substructs that group App state by concern, keeping `app.rs` itself
//! focused on lifecycle, the event loop, and orchestration rather than the
//! working data the tabs visualize.
//!
//! As Phase 2 of the refactoring plan progresses, this module will grow
//! `AppConfig` (user_config, theme, graph_style) alongside [`AppCaches`]
//! and [`AppUiState`].

use std::collections::{HashMap, HashSet, VecDeque};

use ratatui::layout::Rect;

use crate::app::{
    default_sort_states, ConnectionGroup, ConnectionStateFilter, IfaceChangeEvent, InterfaceFilter,
    StatsRange, StreamDirectionFilter, Tab, TimelineFilter, TimelineWindow, UiScrollState,
    ViewMode,
};
use crate::config::NetwatchConfig;
use crate::platform::InterfaceInfo;
use crate::sort::TabSortState;
use crate::ui::sort_picker::SortPickerState;

/// Bounded business caches accumulated across the session — sparkline
/// histories, the bookmarks set, the iface-change log. None of these belong
/// to a single collector; they're cross-cutting derived state that the tick
/// loop and various UI tabs both touch. Grouping them under one substruct
/// keeps `App` itself focused on lifecycle + handles rather than the working
/// data the tabs visualize.
#[derive(Default)]
pub struct AppCaches {
    /// Connection IDs the user has bookmarked. Toggled with `b`; surfaces in
    /// the Packets tab; cleared with `B`.
    pub bookmarks: HashSet<u64>,
    /// Per-remote-IP RTT history for sparklines (keyed by remote IP string).
    /// Bounded by `MAX_RTT_HISTORY_IPS` keys; oldest-inserted IP is evicted
    /// via `rtt_history_order` when a new IP would push the map past the cap.
    pub rtt_history: HashMap<String, VecDeque<f64>>,
    /// FIFO of remote IPs in the order they first appeared in `rtt_history`.
    /// Drives bounded eviction when the keyset exceeds `MAX_RTT_HISTORY_IPS`.
    pub rtt_history_order: VecDeque<String>,
    /// Rolling RX rate history per grouped (process, host) for the Dashboard
    /// Top Connections sparkline. Updated each connection-collector tick.
    pub top_conn_history: HashMap<(String, String), VecDeque<u64>>,
    /// Rolling RX rate history per (process, pid) for the Process drill-in
    /// chart. Updated each connection-collector tick.
    pub top_proc_rx_history: HashMap<(String, Option<u32>), VecDeque<u64>>,
    /// Recent interface up/down/IP-changed events surfaced on the Timeline tab.
    /// Populated when info_tick detects a delta from the previous snapshot.
    pub iface_events: VecDeque<IfaceChangeEvent>,
    /// Snapshot of the previous interface_info, used to detect changes on the
    /// next info_tick. Empty until the second info refresh.
    pub prev_interface_info: Vec<InterfaceInfo>,
    /// Stream indexes whose handshake RTT we've already sampled into
    /// `rtt_history`. Prevents double-counting if the same handshake shows
    /// up across multiple `sample_rtt_from_streams` calls.
    pub rtt_sampled_streams: HashSet<u32>,
}

/// State owned by the Lite view (`src/ui/lite.rs`).
///
/// Kept in its own substruct rather than scattered across [`AppUiState`] so
/// the Lite surface stays legible and auditable — the design brief caps it at
/// a selection, one toggle, and one filter, and a substruct makes creep
/// visible in review.
#[derive(Default)]
pub struct LiteState {
    /// Index into the *filtered* talker list.
    pub selected: usize,
    /// First talker row shown, for scrolling past the visible window.
    pub offset: usize,
    /// Detail block expanded beneath the selected row (`↵`).
    pub detail_open: bool,
    /// `/` filter is accepting keystrokes.
    pub filter_input: bool,
    /// Live query text — matched incrementally against process *or* host.
    pub filter_text: String,
}

/// All UI-controlled state: the active tab, scroll/sort/selection state,
/// chip-row filter selections, in-progress filter input buffers, modal
/// flags (help/settings/memory_stats/geo), transient status messages with
/// their tick counters, and the settings cursor + edit buffer.
///
/// Construction is driven by [`AppUiState::from_config`] because several
/// fields (initial tab, packet_follow flag, geo toggle, timeline window)
/// are seeded from the persisted [`NetwatchConfig`] on startup. Everything
/// else gets a sensible zero-value default.
///
/// Future tests can construct an `AppUiState` directly and exercise event
/// handlers (filter parsing, settings cursor movement, status fade timers)
/// without needing to spin up any collector threads.
/// Ordering for the Egress tree. Volume first by default: on a screen whose
/// job is "what left this machine", the biggest talker is the story.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EgressSort {
    #[default]
    Volume,
    Active,
    Process,
    LastSeen,
    Risk,
}

impl EgressSort {
    pub const ALL: &'static [EgressSort] = &[
        EgressSort::Volume,
        EgressSort::Active,
        EgressSort::Process,
        EgressSort::LastSeen,
        EgressSort::Risk,
    ];
    pub fn label(self) -> &'static str {
        match self {
            EgressSort::Volume => "volume",
            EgressSort::Active => "active",
            EgressSort::Process => "process",
            EgressSort::LastSeen => "last seen",
            EgressSort::Risk => "risk",
        }
    }
    pub fn next(self) -> EgressSort {
        let i = EgressSort::ALL.iter().position(|x| *x == self).unwrap_or(0);
        EgressSort::ALL[(i + 1) % EgressSort::ALL.len()]
    }
}

pub struct AppUiState {
    pub current_tab: Tab,
    /// Full tabbed TUI vs the single-screen Lite view. Opt-in only.
    pub view_mode: ViewMode,
    pub lite: LiteState,
    pub scroll: UiScrollState,
    pub sort_states: HashMap<Tab, TabSortState>,
    pub sort_picker: SortPickerState,

    pub paused: bool,
    pub last_area: Rect,
    pub selected_interface: Option<usize>,

    // ── Chip-row filter selections ──
    pub interface_filter: InterfaceFilter,
    pub connection_state_filter: ConnectionStateFilter,
    pub connection_group: ConnectionGroup,
    pub stats_range: StatsRange,
    pub timeline_filter: TimelineFilter,
    pub timeline_window: TimelineWindow,

    // ── Text-filter input state (per-tab `/` filters) ──
    pub packet_filter_input: bool,
    pub packet_filter_text: String,
    pub packet_filter_active: Option<String>,
    pub connection_filter_input: bool,
    pub connection_filter_text: String,
    pub connection_filter_active: Option<String>,
    pub egress_filter_input: bool,
    pub egress_filter_text: String,
    pub egress_filter_active: Option<String>,

    // ── Egress-tab specifics ──
    /// Which processes' destination rows are folded. Carries a default plus
    /// exceptions rather than a set of names, so a process first seen after
    /// the user folded everything arrives folded too — see
    /// [`crate::ui::tree::FoldState`].
    pub egress_collapsed: crate::ui::tree::FoldState,
    /// Column the Egress tree is ordered by.
    pub egress_sort: EgressSort,
    /// Whether the destination detail pane is open (`d`).
    pub egress_detail: bool,
    /// Which connection groups are folded. Keyed by group value (process
    /// name or remote host), so the fold survives re-sorting and the list
    /// churning between ticks.
    pub connection_collapsed: crate::ui::tree::FoldState,

    /// Process whose rule removal is awaiting confirmation (`x`, then `y`).
    ///
    /// Removal is the only destructive action on this tab — it can discard
    /// hand-written allowlist entries that no amount of re-observation will
    /// bring back, since promotion only ever regenerates what was *seen*. So
    /// it asks, unlike promote, which is additive and therefore safe to fire
    /// on a single keystroke.
    pub egress_pending_removal: Option<String>,

    // ── Packet-tab specifics ──
    pub packet_follow: bool,
    /// When true, the detail pane grows to fill most of the visible
    /// area (and the packet list shrinks). Toggled with `d`. Useful
    /// when the selected packet has a lot of DPI/JA4 output that
    /// doesn't fit in the default 16-line pane.
    pub packet_detail_expanded: bool,
    pub stream_view_open: bool,
    pub stream_view_index: Option<u32>,
    pub stream_direction_filter: StreamDirectionFilter,
    pub stream_hex_mode: bool,
    /// Packet id whose stream segment the stream view should highlight and
    /// scroll to on open — the packet that was selected when `s` was pressed.
    pub stream_view_focus_packet: Option<u64>,

    // ── Modal / overlay flags ──
    pub show_help: bool,
    pub show_memory_stats: bool,
    pub show_geo: bool,
    pub show_settings: bool,
    pub traceroute_view_open: bool,

    // ── Settings UI state ──
    pub settings_cursor: usize,
    pub settings_editing: bool,
    pub settings_edit_buf: String,
    pub settings_status: Option<String>,
    pub settings_status_tick: u32,

    // ── Transient status messages ──
    pub export_status: Option<String>,
    pub export_status_tick: u32,
}

impl AppUiState {
    /// Mirror the pre-substruct App::new() init: seed from `NetwatchConfig`
    /// for the persisted-on-disk fields (initial tab, packet_follow, geo
    /// toggle, timeline window), everything else zeroed.
    pub fn from_config(cfg: &NetwatchConfig) -> Self {
        Self {
            current_tab: cfg.tab(),
            view_mode: ViewMode::default(),
            lite: LiteState::default(),
            scroll: UiScrollState::default(),
            sort_states: default_sort_states(),
            sort_picker: SortPickerState::default(),

            paused: false,
            last_area: Rect::default(),
            selected_interface: None,

            interface_filter: InterfaceFilter::Active,
            connection_state_filter: ConnectionStateFilter::All,
            connection_group: ConnectionGroup::Process,
            stats_range: StatsRange::Session,
            timeline_filter: TimelineFilter::All,
            timeline_window: cfg.timeline_window_enum(),

            packet_filter_input: false,
            packet_filter_text: String::new(),
            packet_filter_active: None,
            connection_filter_input: false,
            connection_filter_text: String::new(),
            connection_filter_active: None,
            egress_filter_input: false,
            egress_filter_text: String::new(),
            egress_filter_active: None,
            egress_collapsed: crate::ui::tree::FoldState::new(cfg.groups_start_collapsed),
            egress_sort: EgressSort::default(),
            egress_detail: false,
            connection_collapsed: crate::ui::tree::FoldState::new(cfg.groups_start_collapsed),
            egress_pending_removal: None,

            packet_follow: cfg.packet_follow,
            packet_detail_expanded: false,
            stream_view_open: false,
            stream_view_index: None,
            stream_direction_filter: StreamDirectionFilter::Both,
            stream_hex_mode: false,
            stream_view_focus_packet: None,

            show_help: false,
            show_memory_stats: false,
            show_geo: cfg.show_geo,
            show_settings: false,
            traceroute_view_open: false,

            settings_cursor: 0,
            settings_editing: false,
            settings_edit_buf: String::new(),
            settings_status: None,
            settings_status_tick: 0,

            export_status: None,
            export_status_tick: 0,
        }
    }
}
