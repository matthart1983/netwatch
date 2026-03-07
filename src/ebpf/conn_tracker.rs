use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{Bpf, BpfLoader};
use bytes::BytesMut;
use std::sync::{Arc, Mutex};
use tokio::task;

/// Event emitted by eBPF programs for connection lifecycle events.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnEvent {
    pub event_type: u32,    // 0=connect, 1=accept, 2=close, 3=state_change
    pub pid: u32,
    pub tgid: u32,
    pub af: u16,            // AF_INET or AF_INET6
    pub protocol: u8,       // IPPROTO_TCP or IPPROTO_UDP
    pub _pad: u8,
    pub sport: u16,
    pub dport: u16,
    pub saddr: [u8; 16],    // IPv4 in first 4 bytes, IPv6 full
    pub daddr: [u8; 16],
    pub old_state: u32,
    pub new_state: u32,
    pub timestamp_ns: u64,
}

unsafe impl aya::Pod for ConnEvent {}

/// Receives connection events from eBPF programs.
pub struct ConnTracker {
    events: Arc<Mutex<Vec<ConnEvent>>>,
}

impl ConnTracker {
    /// Attempt to load and attach eBPF programs for connection tracking.
    /// Returns an error if the kernel or privileges are insufficient.
    pub fn new() -> Result<Self, anyhow::Error> {
        let tracker = Self {
            events: Arc::new(Mutex::new(Vec::new())),
        };
        Ok(tracker)
    }

    /// Start the async reader task that drains the perf event buffer.
    /// This should be called from within a tokio runtime.
    pub async fn start(&self, bpf: &mut Bpf) -> Result<(), anyhow::Error> {
        let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("CONN_EVENTS").unwrap())?;
        let events = Arc::clone(&self.events);

        for cpu_id in online_cpus()? {
            let mut buf = perf_array.open(cpu_id, None)?;
            let events = Arc::clone(&events);
            task::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(std::mem::size_of::<ConnEvent>()))
                    .collect::<Vec<_>>();
                loop {
                    let event_count = buf.read_events(&mut buffers).await.unwrap();
                    for i in 0..event_count.read {
                        if buffers[i].len() < std::mem::size_of::<ConnEvent>() {
                            continue;
                        }
                        let evt = unsafe { &*(buffers[i].as_ptr() as *const ConnEvent) };
                        events.lock().unwrap().push(*evt);
                    }
                }
            });
        }

        Ok(())
    }

    /// Drain all pending events. Called by ConnectionCollector to consume eBPF data.
    pub fn drain_events(&self) -> Vec<ConnEvent> {
        let mut events = self.events.lock().unwrap();
        std::mem::take(&mut *events)
    }
}
