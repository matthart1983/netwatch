//! DHCP / BOOTP classifier.
//!
//! Port-gated to UDP 67/68 by `classify_once`, so recognizing the message is
//! just reading the BOOTP `op` byte (1 = BOOTREQUEST, 2 = BOOTREPLY). We do
//! not parse options here; the Info-string layer renders a short label from
//! the op code.

use super::{AppProtocol, Classifier};

pub struct DhcpClassifier;

impl Classifier for DhcpClassifier {
    fn classify(&self, payload: &[u8], _is_tcp: bool) -> Option<AppProtocol> {
        payload.first().map(|&op| AppProtocol::Dhcp { op })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootrequest_and_bootreply() {
        assert_eq!(
            DhcpClassifier.classify(&[0x01, 0, 0, 0], false),
            Some(AppProtocol::Dhcp { op: 1 })
        );
        assert_eq!(
            DhcpClassifier.classify(&[0x02, 0, 0, 0], false),
            Some(AppProtocol::Dhcp { op: 2 })
        );
    }

    #[test]
    fn empty_is_none() {
        assert_eq!(DhcpClassifier.classify(&[], false), None);
    }
}
