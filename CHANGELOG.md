# Changelog

## 1.0.0 (2026-10-07)

First public release.

- sshd parser for syslog and RFC 3339 timestamps (Debian/Ubuntu `auth.log`, RHEL `secure`)
- Apache/Nginx access log parser (Common and Combined formats, gzip support)
- Detectors: SSH brute force, login after brute force, user enumeration, distributed
  attacks, root logins, web login brute force, 404 scanning bursts, scanner user agents,
  SQLi, XSS, path traversal/LFI, command injection, Log4Shell, Shellshock and sensitive
  file probes
- Per-IP threat score (0-100)
- Rich terminal report plus JSON, CSV (formula-injection safe) and standalone HTML exports
- `--fail-on` exit codes for cron and CI usage
