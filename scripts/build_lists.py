#!/usr/bin/env python3
"""
Safe Tunnel feed builder.

Downloads the VPN Gate list, probes servers, and writes two SEPARATE lists:
  sstp.json         - servers that really answer the SSTP handshake request
  openvpn_tcp.json  - servers that really answer an OpenVPN TCP hard-reset
Each file is optionally signed (ECDSA P-256 / SHA-256) -> <file>.sig

Only the Python standard library is needed for building; `cryptography` is needed only for signing.
Test hooks (environment): FEED_CSV (local CSV file), FEED_ALLOW_PRIVATE=1, FEED_SSTP_PORT, FEED_OVPN_PORTS.
"""
import argparse, base64, binascii, concurrent.futures as cf, csv, hashlib, io, ipaddress, json, os
import random, re, socket, ssl, struct, sys, time, urllib.request, uuid
from datetime import datetime, timezone

SOURCES = ["https://www.vpngate.net/api/iphone/", "http://www.vpngate.net/api/iphone/"]
PUBLISH_N = int(os.environ.get("FEED_PUBLISH_N", "20"))   # servers published per list (app shows the best 10 after local probing)
CANDIDATES = int(os.environ.get("FEED_CANDIDATES", "150")) # top-by-score servers probed per protocol
WORKERS = int(os.environ.get("FEED_WORKERS", "10"))
TIMEOUT = float(os.environ.get("FEED_TIMEOUT", "6"))
ALLOW_PRIVATE = os.environ.get("FEED_ALLOW_PRIVATE") == "1"
SSTP_PORT = int(os.environ.get("FEED_SSTP_PORT", "443"))
EXTRA_TCP_PORTS = [int(p) for p in os.environ.get("FEED_OVPN_PORTS", "443,992").split(",") if p]
VALID_FOR = 2 * 3600

def now_iso(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ---------------------------------------------------------------- download / parse
def fetch_csv():
    local = os.environ.get("FEED_CSV")
    if local:
        return open(local, encoding="utf-8").read()
    last = None
    for url in SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SafeTunnelFeed/1.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read(40 * 1024 * 1024)
            text = data.decode("utf-8", "replace")
            if "HostName" in text:
                return text
            last = "unexpected content"
        except Exception as e:
            last = repr(e)
    raise SystemExit(f"could not download the VPN Gate list: {last}")

def clean(s, n=64): return "".join(c for c in (s or "") if c.isprintable()).strip()[:n]
def to_int(s):
    try: return int(str(s).strip())
    except Exception: return None

def valid_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and (ALLOW_PRIVATE or a.is_global)

def valid_host(h):
    return bool(re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*", h))

def parse(text):
    lines = [l for l in text.lstrip("\ufeff").splitlines() if l and not l.startswith("*")]
    if not lines or not lines[0].startswith("#"):
        raise SystemExit("CSV header not found (format changed?)")
    lines[0] = lines[0].lstrip("#")
    rows = list(csv.DictReader(io.StringIO("\n".join(lines))))
    out, seen = [], set()
    for r in rows:
        ip = (r.get("IP") or "").strip()
        host = (r.get("HostName") or "").strip()
        if not valid_ip(ip) or ip in seen or (host and not valid_host(host)):
            continue
        seen.add(ip)
        cc = (r.get("CountryShort") or "").strip().upper()
        out.append({
            "ip": ip, "host": host, "country_code": cc if re.fullmatch(r"[A-Z]{2}", cc) else "",
            "country": clean(r.get("CountryLong")), "score": to_int(r.get("Score")) or 0,
            "ping_ms": to_int(r.get("Ping")), "speed_bps": to_int(r.get("Speed")),
            "sessions": to_int(r.get("NumVpnSessions")), "uptime_ms": to_int(r.get("Uptime")),
            "ovpn_b64": (r.get("OpenVPN_ConfigData_Base64") or "").strip(),
        })
    out.sort(key=lambda s: s["score"], reverse=True)
    return out

def sstp_host(s):
    h = s["host"]
    if not h: return s["ip"]
    return h if "." in h else h + ".opengw.net"

# ---------------------------------------------------------------- SSTP probe
def probe_sstp(s):
    ip, host = s["ip"], sstp_host(s)
    for trusted in (True, False):
        try:
            t0 = time.monotonic()
            raw = socket.create_connection((ip, SSTP_PORT), timeout=TIMEOUT)
            tcp_ms = int((time.monotonic() - t0) * 1000)
            raw.settimeout(TIMEOUT)
            ctx = ssl.create_default_context()
            if not trusted:                      # inspect-only pass: nothing secret is sent
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            try:
                ss = ctx.wrap_socket(raw, server_hostname=host)
            except ssl.SSLCertVerificationError:
                raw.close()
                if trusted: continue
                return None
            with ss:
                req = ("SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
                       "Content-Length: 18446744073709551615\r\n"
                       f"Host: {host}\r\nSSTPCORRELATIONID: {{{uuid.uuid4()}}}\r\n\r\n").encode()
                ss.sendall(req)
                line = b""
                while len(line) < 200 and not line.endswith(b"\n"):
                    ch = ss.recv(1)
                    if not ch: break
                    line += ch
                if not line.startswith(b"HTTP/1.1 200"):
                    return None
                der = ss.getpeercert(binary_form=True)
            return {"tcp_ms": tcp_ms, "tls_trusted": trusted,
                    "cert_sha256": hashlib.sha256(der).hexdigest().upper() if der else None,
                    "checked_at": now_iso()}
        except Exception:
            return None
    return None

# ---------------------------------------------------------------- OpenVPN config handling
ALLOWED = {"dev", "dev-type", "nobind", "persist-key", "persist-tun", "resolv-retry", "cipher",
           "data-ciphers", "data-ciphers-fallback", "auth", "comp-lzo", "compress", "reneg-sec", "remote-cert-tls",
           "tls-client", "mute-replay-warnings", "tun-mtu", "mssfix", "tls-cipher", "key-direction", "ping",
           "ping-restart", "connect-retry", "connect-timeout", "sndbuf", "rcvbuf", "tls-version-min", "pull",
           "auth-nocache", "verb"}
BLOCKS = {"ca", "cert", "key", "tls-auth", "tls-crypt"}

def read_config(b64):
    try:
        return base64.b64decode(b64, validate=False).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None

def config_facts(text):
    proto, remotes = None, []
    for l in text.splitlines():
        p = l.split("#")[0].split(";")[0].split()
        if not p: continue
        if p[0] == "proto" and len(p) > 1: proto = p[1].lower()
        if p[0] == "remote" and len(p) > 2 and p[2].isdigit(): remotes.append((p[1], int(p[2])))
    tls_wrap = any(l.strip().startswith(("<tls-auth>", "<tls-crypt>", "tls-auth ", "tls-crypt ")) for l in text.splitlines())
    return proto, remotes, tls_wrap

def sanitize_config(text, ip, port):
    """Whitelist rebuild: drops script/plugin/up/down/etc. directives from third-party configs; forces TCP."""
    out, i, lines = ["client", "proto tcp", f"remote {ip} {port}", "auth-user-pass"], 0, text.splitlines()
    while i < len(lines):
        t = lines[i].strip(); i += 1
        m = re.fullmatch(r"<([\w-]+)>", t)
        if m:
            tag, body = m.group(1), []
            while i < len(lines) and lines[i].strip() != f"</{tag}>":
                body.append(lines[i]); i += 1
            i += 1
            if tag in BLOCKS: out += [f"<{tag}>"] + body + [f"</{tag}>"]
            continue
        p = t.split("#")[0].split(";")[0].split()
        if p and p[0] in ALLOWED:
            out.append(" ".join(p))
    return "\n".join(out) + "\n"

# ---------------------------------------------------------------- OpenVPN probe
def ovpn_hard_reset(ip, port):
    """TCP connect, send P_CONTROL_HARD_RESET_CLIENT_V2, expect P_CONTROL_HARD_RESET_SERVER_V2 (opcode 8)."""
    t0 = time.monotonic()
    sock = socket.create_connection((ip, port), timeout=TIMEOUT)
    tcp_ms = int((time.monotonic() - t0) * 1000)
    try:
        sock.settimeout(TIMEOUT)
        pkt = bytes([7 << 3]) + os.urandom(8) + b"\x00" + struct.pack(">I", 0)
        sock.sendall(struct.pack(">H", len(pkt)) + pkt)
        hdr = b""
        while len(hdr) < 3:
            c = sock.recv(3 - len(hdr))
            if not c: return tcp_ms, False
            hdr += c
        return tcp_ms, (hdr[2] >> 3) == 8
    except Exception:
        return tcp_ms, False
    finally:
        sock.close()

def probe_ovpn(s):
    text = read_config(s["ovpn_b64"]) if s["ovpn_b64"] else None
    if not text: return None
    proto, remotes, tls_wrap = config_facts(text)
    ports = []
    if proto == "tcp":
        ports += [p for h, p in remotes if h == s["ip"]] or [p for _, p in remotes]
    ports += [p for p in EXTRA_TCP_PORTS if p not in ports]   # config may list only UDP; try common TCP ports
    for port in ports[:4]:
        try:
            tcp_ms, ok = ovpn_hard_reset(s["ip"], port)
        except Exception:
            continue
        # With tls-auth/tls-crypt the server silently ignores a plain reset, so only the TCP connect can be shown.
        if ok or tls_wrap:
            return {"port": port, "tcp_ms": tcp_ms, "handshake": "reset-reply" if ok else "tcp-only",
                    "config_b64": base64.b64encode(sanitize_config(text, s["ip"], port).encode()).decode(),
                    "checked_at": now_iso()}
    return None

# ---------------------------------------------------------------- orchestration
def run_probes(servers, fn):
    res = []
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for s, r in zip(servers, ex.map(fn, servers)):
            if r: res.append((s, r))
    return res

def common(s):
    return {"ip": s["ip"], "host": s["host"], "country_code": s["country_code"], "country": s["country"],
            "score": s["score"], "published_ping_ms": s["ping_ms"], "published_speed_bps": s["speed_bps"],
            "published_sessions": s["sessions"], "published_uptime_ms": s["uptime_ms"]}

def rank(items):
    # primary: VPN Gate score; tie-break: fewer sessions, then lower measured connect time
    return sorted(items, key=lambda x: (-x[0]["score"], x[0]["sessions"] or 0, x[1]["tcp_ms"]))[:PUBLISH_N]

def write_list(outdir, name, protocol, servers):
    path = os.path.join(outdir, name)
    doc = {"schema": 1, "protocol": protocol, "generatedAt": now_iso(), "validForSeconds": VALID_FOR,
           "source": "vpngate.net", "servers": servers}
    data = json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8")
    with open(path, "wb") as f: f.write(data)
    key = os.environ.get("SIGNING_KEY_PEM")
    if key:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        pk = serialization.load_pem_private_key(key.encode(), password=None)
        sig = pk.sign(data, ec.ECDSA(hashes.SHA256()))
        with open(path + ".sig", "w") as f: f.write(base64.b64encode(sig).decode())
    else:
        print("WARNING: SIGNING_KEY_PEM not set - list is published unsigned", file=sys.stderr)

MIN_ACCEPT = int(os.environ.get("FEED_MIN_ACCEPT", "3"))   # fewer healthy servers than this -> keep the previous list

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="out"); a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    servers = parse(fetch_csv())
    print(f"parsed {len(servers)} valid servers")
    if not servers: raise SystemExit("no servers parsed")
    cands = servers[:CANDIDATES]

    sstp = rank(run_probes(cands, probe_sstp))
    print(f"SSTP confirmed (published): {len(sstp)}")
    ovpn = rank(run_probes([s for s in cands if s["ovpn_b64"]], probe_ovpn))
    print(f"OpenVPN-TCP confirmed (published): {len(ovpn)}")

    wrote = 0
    if len(sstp) >= MIN_ACCEPT:
        write_list(a.out, "sstp.json", "sstp", [dict(common(s), sstp_host=sstp_host(s), port=SSTP_PORT, probe=r) for s, r in sstp]); wrote += 1
    else: print("SSTP list too small - keeping the previous one", file=sys.stderr)
    if len(ovpn) >= MIN_ACCEPT:
        write_list(a.out, "openvpn_tcp.json", "openvpn-tcp", [dict(common(s), port=r["port"], probe={k: v for k, v in r.items() if k != "config_b64"}, config_b64=r["config_b64"]) for s, r in ovpn]); wrote += 1
    else: print("OpenVPN list too small - keeping the previous one", file=sys.stderr)
    if wrote == 0: raise SystemExit("nothing publishable this run")

if __name__ == "__main__":
    main()
