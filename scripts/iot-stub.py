#!/usr/bin/env python3
"""Atrapa urzadzen IoT do testowania sygnatur ASI bez labu (tylko 127.0.0.1).

Serwuje na http://127.0.0.1:18080 cztery "urzadzenia":
  /                       kamera Hikvision (naglowek Server: GoAhead-Webs)
  /cgi-bin/luci           OpenWrt LuCI
  /general/status.html    drukarka HP
  /rootDesc.xml           opis urzadzenia UPnP
  cokolwiek innego        ogolna kamera IP ("IP Camera", DVR, login)
Kazde inne zachowanie (404) nie jest potrzebne - test sprawdza trafienia pozytywne
i brak falszywych trafien dla sygnatur Dahua / MikroTik / NAS.

Uzycie:
  python3 scripts/iot-stub.py &          # w tle
  nuclei -t signatures/http -u http://127.0.0.1:18080 -nc -duc -ni
  curl -s http://127.0.0.1:18080/ | head
"""
import http.server
import socketserver

PAGES = {
    "/": b"""<html><head><title>Hikvision Login</title></head><body>
<form><input name="username"><input type="password" name="password">
<input type="submit" value="Login"></form><p>DS-2CD2143G0-I</p></body></html>""",
    "/cgi-bin/luci": b"""<html><head><title>LuCI - OpenWrt Configuration</title></head><body>OpenWrt</body></html>""",
    "/general/status.html": b"""<html><head><title>HP LaserJet M404</title></head><body>Printer status: toner 80%, paper tray 1 ok</body></html>""",
    "/rootDesc.xml": b"""<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<friendlyName>Router</friendlyName><manufacturer>ACME</manufacturer><modelName>ACME-RT1</modelName>
</device></root>""",
}
FALLBACK = b"""<html><head><title>IP Camera Login</title></head><body>
Network Camera - DVR / NVR login: <input type="password"></body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "GoAhead-Webs"
    sys_version = ""

    def do_GET(self):
        body = PAGES.get(self.path, FALLBACK)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("127.0.0.1", 18080), Handler) as srv:
        print("atrapa IoT: http://127.0.0.1:18080 (Ctrl+C konczy)")
        srv.serve_forever()
