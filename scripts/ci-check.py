#!/usr/bin/env python3
"""Sprawdza wyniki czystego startu (.github/workflows/clean-start.yml) przez API panelu i DefectDojo.

Uzycie (po make up && make demo): python3 scripts/ci-check.py demo | full | persisted
Oczekiwania: docker/lab/compose.yml i docs/guide/jury.md.
"""
import glob
import http.cookiejar
import json
import os
import sys
import urllib.parse
import urllib.request

env = {}
with open(".env") as f:
    for line in f:
        key, sep, val = line.strip().partition("=")
        if sep and not key.startswith("#"):
            env[key] = val

PANEL = "http://" + env.get("ASI_WEB_ADDR", "127.0.0.1:18090")
DD = "http://127.0.0.1:" + env.get("DD_PORT", "8080")
failed = []


def check(name, ok, got=""):
    print(("  OK   " if ok else "  FAIL ") + name + ("" if ok else f"  -> {got}"), flush=True)
    if not ok:
        failed.append(name)


def call(opener, url, body=None, headers=None):
    req = urllib.request.Request(url, None if body is None else json.dumps(body).encode(),
                                 {"Content-Type": "application/json", **(headers or {})})
    with opener.open(req, timeout=30) as r:
        return json.load(r)


panel = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
call(panel, PANEL + "/api/v1/login",
     {"username": env.get("ASI_ADMIN_USER", "admin"), "password": env["ASI_ADMIN_PASSWORD"]})


def get(path):
    return call(panel, PANEL + "/api/v1/" + path) or []


def run_dirs(root):
    return sorted(os.path.dirname(p) for p in glob.glob(f"results/{root}/*/run.json"))


def load(path):
    with open(path) as f:
        return json.load(f) or []


def demo():
    runs = run_dirs("lab")
    check("dwa przebiegi", len(runs) == 2, runs)
    if len(runs) != 2:
        return
    for r in runs:
        status = load(r + "/run.json")["status"]
        check(f"przebieg {os.path.basename(r)} zakonczony", status == "done", status)

    def ports(run):
        return {o["asset_key"] for o in load(run + "/observations.json") if o["kind"] == "port"}

    first, second = ports(runs[0]), ports(runs[1])
    print("  skan 1:", sorted(first))
    print("  skan 2:", sorted(second))
    # .17 celowo miga co 30 s, wiec nie jest warunkiem
    for key, host in [("10/tcp/80", "web-prod"), ("10/tcp/443", "web-prod TLS"), ("11/tcp/80", "wordpress"),
                      ("13/tcp/6379", "redis"), ("14/tcp/23", "legacy telnet"), ("14/tcp/8000", "legacy www"),
                      ("15/tcp/80", "app")]:
        check(f"skan 1 widzi {host}", "192.0.2." + key in first, key)
    check("skan 1 widzi staging-admin", any(k.startswith("192.0.2.12/") for k in first))
    check("skan 2 widzi nowy jenkins", "192.0.2.16/tcp/8080" in second)
    check("skan 2 nie widzi legacy", not any(k.startswith("192.0.2.14/") for k in second))

    events = get("runs/" + os.path.basename(runs[1]) + "/events")
    by_type = {}
    for e in events:
        by_type.setdefault(e["type"], set()).add(e["key"])
    print("  zdarzenia:", {t: sorted(k) for t, k in by_type.items()})
    check("jenkins = new", "192.0.2.16/tcp/8080" in by_type.get("new", ()))
    check("app = changed", "192.0.2.15/tcp/80" in by_type.get("changed", ()))
    check("legacy = missing", any(k.startswith("192.0.2.14") for k in by_type.get("missing", ())))
    stable = ("192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13")
    wrong = [k for t in ("missing", "gone", "changed") for k in by_type.get(t, ()) if k.split("/")[0] in stable]
    check("brak falszywych zmian na stalych hostach", not wrong, wrong)

    sigs = {(o["asset_key"], o["data"]["id"]) for r in runs for o in load(r + "/observations.json")
            if o["kind"] == "signature"}
    check("sygnatura redis bez hasla", ("192.0.2.13/tcp/6379", "asi-redis-noauth") in sigs, sorted(sigs))
    for ip, what in [("11", "wordpress"), ("12", "staging/admin"), ("16", "jenkins")]:
        check(f"sygnatury na {what}", any(k.startswith(f"192.0.2.{ip}/") for k, _ in sigs))

    anon = urllib.request.build_opener()
    token = call(anon, DD + "/api/v2/api-token-auth/",
                 {"username": env.get("DD_ADMIN_USER", "admin"), "password": env["DD_ADMIN_PASSWORD"]})["token"]
    auth = {"Authorization": "Token " + token}
    count = call(anon, DD + "/api/v2/findings/?limit=1", headers=auth)["count"]
    check("DefectDojo ma znaleziska", count > 0, count)
    titles = {t.get("title") for t in call(anon, DD + "/api/v2/tests/?limit=100", headers=auth)["results"]}
    for title in ("ASI discovery", "asi-changes", "asi-httpx", "asi-nuclei"):
        check(f"DefectDojo: test {title}", title in titles, titles)


def full():
    runs = run_dirs("ci-full")
    check("pelny skan zapisany", len(runs) == 1, runs)
    if runs:
        found = [f'{s.get("ip")}:{s.get("port")}' for s in load(runs[-1] + "/services.json")]
        check("pelny TCP znajduje redis (nie 0 uslug)", "192.0.2.13:6379" in found, found)


def persisted():
    keys = {a["key"] for a in get("assets?" + urllib.parse.urlencode({"q": "192.0.2."}))}
    check("po restarcie sa assety", {"192.0.2.13/tcp/6379", "192.0.2.16/tcp/8080"} <= keys, sorted(keys))
    check("po restarcie jest historia skanow", len(get("runs")) >= 3)


{"demo": demo, "full": full, "persisted": persisted}[sys.argv[1]]()
print(f"Wynik: {len(failed)} FAIL")
sys.exit(1 if failed else 0)
