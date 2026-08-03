#!/usr/bin/env python3
# YTUnlock 崩溃日志接收端
# 用法: python3 collector.py [port]   默认 8099
# dylib 会 POST 到 http://<你的服务器IP>:8099/report
# 收到的日志按设备+时间存到 ./ytlogs/ 下，并实时打印到控制台。

import sys, os, time, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ytlogs")
os.makedirs(OUT, exist_ok=True)

class H(BaseHTTPRequestHandler):
    def _ok(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        self._ok()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n) if n else b""
        ts = time.strftime("%Y%m%d-%H%M%S")
        # 从 header 里取设备标识（dylib 会带上）
        dev = self.headers.get("X-Device", "unknown").replace("/", "_")[:40]
        tag = self.headers.get("X-Tag", "log")
        fn = os.path.join(OUT, f"{ts}_{dev}_{tag}.log")
        with open(fn, "wb") as f:
            f.write(body)
        print("\n" + "=" * 70)
        print(f"[{ts}] from {dev} tag={tag} ({len(body)} bytes) -> {fn}")
        print("-" * 70)
        try:
            print(body.decode("utf-8", "replace"))
        except Exception:
            print(repr(body))
        print("=" * 70)
        self._ok()

    def log_message(self, *a):
        pass  # 静音默认访问日志

if __name__ == "__main__":
    print(f"YTUnlock collector listening on 0.0.0.0:{PORT}")
    print(f"logs saved to: {OUT}")
    print(f"dylib should POST to: http://<SERVER_IP>:{PORT}/report")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
