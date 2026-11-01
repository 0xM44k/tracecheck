# Changelog

## 0.1.0

Initial release.

- `verify`: safe-level canaries for shell execution, system-information
  discovery, shadow-file read, file permission change, and loopback
  network connect (Linux); full-level canaries additionally for cron,
  systemd, profile.d persistence and account creation (Linux) and their
  Windows equivalents (scheduled task, Run key, service, account).
- Host-configuration reading and prediction for Linux (`auditctl`,
  `auditd.conf`, `journalctl`, syslog files) and Windows (`auditpol`,
  `reg query`, `wevtutil`, `sc query`).
- `rules`: generates deduplicated `auditd` rules / Windows commands from a
  verify report's blind checks, or for an explicit ID list. Never applies
  configuration itself.
- `watch`: decoy-file deception with four containment modes (`alert`,
  `deny`, `suspend`, `kill`) and an allow-list, backed by `fanotify`
  permission events on Linux and SACL + Security-log polling on Windows.
- `monitor`: persists per-check status between runs and raises an alert on
  regression (covered → not covered) and recovery.
- JSON, text, and single-file HTML report formats.
- Verified live against a real Linux kernel (auditd) end to end: a clean
  baseline run, generated-rule loading, a fully-covered re-run, live
  `watch` containment in all four modes, and live `monitor`
  regression/recovery detection. Windows is built, `go vet`-clean, and
  exercised live on GitHub Actions' `windows-latest` runner on every push.
- Unit tests across the matching, host-configuration, verification,
  monitor-comparison, rules-generation and report-rendering packages.

### Known gaps (see README for detail)

macOS support, direct eBPF/ETW telemetry verification independent of
auditd/Sysmon, SIEM-forwarding verification, and deep Sysmon-config-aware
prediction are not implemented yet.
