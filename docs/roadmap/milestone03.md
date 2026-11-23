# Milestone 03: Targeted UDP Scanning, Native Protocol Checks & Scan Speed Optimization

## Goal
Close the network blind spot by adding fast targeted UDP discovery/checks, expanding native protocol checks from 15 to ~35 high-signal infrastructure checks, and cutting scan duration on local/LAN targets.

## 1. Targeted UDP Discovery (`internal/discovery`)
- Add a fast, targeted UDP scan stage (enabled in `Full Unauthenticated` and `Infrastructure` scan profiles) covering high-value security UDP ports only (avoiding slow 65k UDP sweeps):
  - Ports: `53` (DNS), `67/68` (DHCP), `69` (TFTP), `111` (RPCbind), `123` (NTP), `137/138` (NetBIOS), `161` (SNMP), `389` (CLDAP), `500` (IKE/IPsec), `514` (Syslog), `623` (IPMI), `1194` (OpenVPN), `1900` (SSDP), `5060` (SIP), `5353` (mDNS).
- Parse `open` and `open|filtered` states cleanly into the per-host Knowledge Base so UDP native checks trigger automatically.

## 2. Expand Native Infrastructure Checks (15 → ~35 High-Signal Checks)
Add deterministic, safe, non-destructive Go checks with clear `firm`/`confirmed` evidence:
- **SMB / Windows Networking:**
  - `SMB-SIGN-001`: SMB signing disabled or not required (relay risk).
  - `SMB-V1-001`: SMBv1 protocol enabled (EternalBlue / legacy protocol exposure).
  - `SMB-NULL-001`: Anonymous/null session IPC$ or share enumeration allowed.
- **UDP & Network Infrastructure:**
  - `SNMP-DEF-001`: SNMP v1/v2c default community strings (`public`, `private`) readable.
  - `NTP-MON-001`: NTP `monlist` / mode 6 control queries enabled (amplification/info leak).
  - `IPMI-AUTH-001`: IPMI 2.0 RAKP cipher 0 authentication bypass or anonymous ping response.
  - `IKE-AGGR-001`: IPsec IKEv1 Aggressive Mode enabled (PSK hash capture risk).
  - 	`TFTP-OPEN-001`: Unauthenticated TFTP service reachable.
- **Directory, Cloud & Container Daemons:**
  - `LDAP-ANON-001`: LDAP anonymous bind / rootDSE base namingContexts disclosure.
  - `DOCKER-API-001`: Unauthenticated Docker Engine API (`2375/tcp`) exposed.
  - `KUBELET-001`: Unauthenticated Kubernetes Kubelet read-only (`10255`) or read-write (`10250`) API exposed.
  - `MONGO-UNAUTH-001` / `ELASTIC-UNAUTH-001` / `MEMCACHED-UNAUTH-001`: Unauthenticated datastore exposure.
- **Cryptography & Transport:**
  - `TLS-EXP-001` / `TLS-SELF-001`: Expired or self-signed X.509 certificate on external/non-dev ports.
  - `TLS-WEAK-001`: TLS 1.0/1.1 or RC4/3DES/EXPORT ciphers accepted.
  - `HTTP-HSTS-001` / `HTTP-SEC-HDR-001`: Missing strict transport security on HTTPS login/admin endpoints (`tentative`/info severity).

## 3. Scan Speed & Profile Tuning
- Introduce timing profiles (`fast-lan`, `standard`, `polite`) instead of hardcoding a slow rate limit across all environments:
  - `fast-lan`: Higher Nmap `--min-rate`, parallel NSE script execution per host, and higher Nuclei request rate for RFC1918/local targets.
  - `polite`: Conservative pacing for fragile appliances or WAN links.
- Target cutting a basic 5-port Docker lab scan from ~3 minutes down to **< 45 seconds** without sacrificing accuracy.

## Acceptance Criteria
1. UDP scan detects open `53/udp`, `161/udp`, or `123/udp` services in lab tests and triggers corresponding native UDP checks.
2. All new native checks declare explicit KB preconditions, record skip reasons when not applicable, and include unit tests with mock network listeners.
3. `fast-lan` profile completes a standard 5-port lab scan in under 45 seconds.