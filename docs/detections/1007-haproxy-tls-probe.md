# 1007 — Unauthorized TLS Probe of Reverse Proxy

| | |
|---|---|
| Rule ID | `1007-haproxy-tls-probe` |
| File | `config/rules/haproxy-tls-probe.yml` |
| Severity | medium |
| Source | `haproxy` |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) / [T1133](https://attack.mitre.org/techniques/T1133/) |
| Status | experimental |

## Rule
Fires on `event_type: tls_handshake_failure` from HAProxy — a TLS handshake
that HAProxy rejected (missing/invalid client certificate, no shared cipher, or
unsupported protocol).

## Risk
This deployment fronts internal services (e.g. Proxmox at
`192.168.178.12:8006`) with a **client-certificate-verifying** HAProxy. A
handshake failure is therefore a connection that could not authenticate to the
proxy. A burst of failures from one external source is either a scanner
fingerprinting the endpoint or someone trying to reach a protected service
without a valid client certificate.

## Implementation
- **Parsing:** `[[extract.rule]] app_name = "haproxy"` extracts `src_ip`,
  `src_port`, `frontend`, `backend` from the connection log line and sets
  `event_type = tls_handshake_failure` when the line contains
  `SSL handshake failure`.
- **Detection:** single-event selection on `_source_type: haproxy` +
  `event_type: tls_handshake_failure`. Volume/scan escalation can be added as a
  correlation on `src_ip` if desired.

## False positives
- A legitimate client whose certificate expired or was misconfigured will
  generate these until fixed — expect a cluster from one known internal IP.
- Health-checkers / uptime monitors that probe the HTTPS port without a client
  cert. Allow-list their source IPs.
- Browsers that cannot present a client cert (user error) — typically low volume
  from an internal address.

## Playbook
1. Group failures by `src_ip` over the last hour. One internal IP with steady
   failures → likely a misconfigured legitimate client; one external IP with
   many → treat as recon.
2. For external sources: check the `backend` they targeted, correlate with
   firewall (`filterlog`) activity from the same IP, and consider blocking at
   pfSense if the source has no business reaching the proxy.
3. For internal sources: verify the client certificate (validity, CA, CN) and
   reissue if needed.
4. Confirm the client-cert requirement is actually enforced on the targeted
   backend (a handshake failure means it was — good).

## Test
`bash tests/detections/test-1007-haproxy-tls-probe.sh` — injects an
`SSL handshake failure` line from an external IP.
