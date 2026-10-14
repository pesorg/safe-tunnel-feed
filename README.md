# safe-tunnel-feed

A scheduled GitHub Actions workflow that downloads the public VPN Gate server list, health-checks the servers, and publishes two separate lists as JSON.

## Output (branch `data`)

| File | Contents |
|---|---|
| `sstp.json` | Servers that answer the SSTP handshake request with HTTP 200 |
| `openvpn_tcp.json` | Servers that answer an OpenVPN TCP hard-reset, with a sanitized TCP `.ovpn` config |
| `*.sig` | Optional ECDSA P-256 / SHA-256 signature of each file |

Each list holds up to 20 servers, ranked by VPN Gate score, then fewer sessions, then lower measured connect time.

Raw URLs:
`https://raw.githubusercontent.com/pesorg/safe-tunnel-feed/data/sstp.json`
`https://raw.githubusercontent.com/pesorg/safe-tunnel-feed/data/openvpn_tcp.json`

## How it works

1. Runs every 2 hours on even UTC hours (`0 */2 * * *`) or manually via **Run workflow**.
2. Downloads the VPN Gate CSV, validates records (public IPv4 only, valid host names, de-duplicated).
3. Probes the top 150 servers by score, 10 at a time:
   - SSTP: TCP 443, TLS, `SSTP_DUPLEX_POST`.
   - OpenVPN: TCP connect, then a hard-reset exchange. If the config is UDP, TCP ports 443 and 992 are tried.
4. Rebuilds each OpenVPN config from a directive whitelist (drops `up`, `script-security`, `plugin`, `<connection>` blocks, etc.) and forces TCP. No credentials are included.
5. Writes the lists and force-pushes a single commit to the `data` branch. If a list has fewer than 3 healthy servers, the previous list is kept.

## Setup

1. Create a **public** repository and upload these files, including the hidden `.github` folder.
2. `Settings → Actions → General → Workflow permissions` → **Read and write**.
3. Optional signing: run `pip install cryptography && python scripts/gen_keys.py`. Save the private key as the repository secret `SIGNING_KEY_PEM`; the printed `PUBLIC_KEY_B64` is the verification key. Without the secret, files are published unsigned.
4. `Actions → update-server-lists → Run workflow`.

## Configuration (environment variables)

`FEED_PUBLISH_N` (20), `FEED_CANDIDATES` (150), `FEED_WORKERS` (10), `FEED_TIMEOUT` (6 s), `FEED_MIN_ACCEPT` (3).

## Output schema

```json
{"schema": 1, "protocol": "sstp | openvpn-tcp", "generatedAt": "<UTC>", "validForSeconds": 7200,
 "servers": [{"ip": "", "host": "", "sstp_host": "", "port": 443, "country_code": "", "country": "",
              "score": 0, "published_*": 0, "probe": {"tcp_ms": 0}, "config_b64": ""}]}
```
`sstp_host` is SSTP only; `config_b64` is OpenVPN only.

## Tests

`python tests/test_feed.py` runs against local fake SSTP and OpenVPN servers (not real VPN Gate servers).

## Notes

- Scheduled runs can start 10–60 minutes late. GitHub may disable schedules after 60 days without repository activity; run the workflow manually to re-enable.
- Not verified against live VPN Gate data or inside GitHub Actions. If a run produces empty lists, check the `Build lists` log lines `parsed …` and `confirmed …`.
- VPN Gate is an academic project; check its terms of use.
