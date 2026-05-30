//! NTP classifier.
//!
//! Port-gated to UDP 123 by `classify_once`. The first byte packs
//! leap-indicator (2 bits), version (3 bits), and mode (3 bits) per RFC 5905;
//! we surface version and mode, which the Info-string layer renders as
//! `NTPv{version} {mode}`.

use super::{AppProtocol, Classifier};

pub struct NtpClassifier;

impl Classifier for NtpClassifier {
    fn classify(&self, payload: &[u8], _is_tcp: bool) -> Option<AppProtocol> {
        payload.first().map(|&b| AppProtocol::Ntp {
            version: (b >> 3) & 0x07,
            mode: b & 0x07,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_mode_v4() {
        // li=0, vn=4 (0b100), mode=3 (client) → 0b00_100_011 = 0x23
        assert_eq!(
            NtpClassifier.classify(&[0x23, 0, 0, 0], false),
            Some(AppProtocol::Ntp {
                version: 4,
                mode: 3
            })
        );
    }

    #[test]
    fn server_mode_v3() {
        // vn=3 (0b011), mode=4 (server) → 0b00_011_100 = 0x1c
        assert_eq!(
            NtpClassifier.classify(&[0x1c, 0, 0, 0], false),
            Some(AppProtocol::Ntp {
                version: 3,
                mode: 4
            })
        );
    }

    #[test]
    fn empty_is_none() {
        assert_eq!(NtpClassifier.classify(&[], false), None);
    }
}
