# Network intelligence

Traffic heuristics can flag scans, beaconing, DNS tunneling and bandwidth thresholds. These are investigative signals, distinct from verified process ownership and Diagnose's evidence contracts. See the [reference](@repo@/docs/REFERENCE.md#network-intelligence).

GeoIP lookups read local databases. In v0.39.0 the old online `ip-api.com` fallback was removed; `geoip_online` is ignored for compatibility. Run `netwatch geoip update` explicitly to download DB-IP data; lookup addresses are not sent by that update. See [GeoIP setup](@repo@/docs/REFERENCE.md#geoip-databases).

WHOIS/RDAP and reverse DNS have different network behavior. `W` requests WHOIS for selected addresses; the [outbound inventory](@repo@/docs/THREAT-MODEL.md#outbound-inventory) states destinations, disclosed data and automatic versus explicit triggers. See [[Configuration and Privacy]].

<!-- include: docs/REFERENCE.md#network-intelligence -->

<!-- include: docs/REFERENCE.md#geoip-databases -->
