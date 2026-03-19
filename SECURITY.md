# Security Analysis

`spank` must run as root (`sudo`) to access the Apple Silicon accelerometer via
IOKit HID. This document records the threat-model analysis performed to ensure
no user data is exfiltrated and to document the hardening measures applied.

---

## Findings Summary

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| S-1 | HIGH | Path traversal in `--custom` / `--custom-files` (root context) | **Fixed** |
| S-2 | MEDIUM | Symlink following in custom audio loading (root context) | **Fixed** |
| S-3 | MEDIUM | String-concatenation path construction in `loadFiles()` | **Fixed** |
| S-4 | LOW | JSON error handler echoed raw user input back to stdout | **Fixed** |
| S-5 | ✅ None | Network / data-exfiltration review | No issues |
| S-6 | ✅ None | Command injection review | No issues |
| S-7 | ✅ None | Dependency telemetry / analytics review | No issues |

---

## Detailed Findings

### S-1 · Path Traversal — HIGH (Fixed)

**Problem:** The `--custom <dir>` flag and `--custom-files <file,...>` flag
previously accepted any user-supplied path without sanitisation. Because the
process runs as root, a malicious invocation such as

```
sudo spank --custom /etc
sudo spank --custom-files /etc/shadow.mp3
```

could allow reading arbitrary system files through error messages or MP3
decoding side-channels.

**Fix:** `validateCustomPath()` and `validateCustomFile()` are now called for
every user-supplied path before it is used:

1. `filepath.Abs(filepath.Clean(p))` removes `..` components and relative
   references.
2. `filepath.EvalSymlinks()` resolves the final target so that indirect
   traversal through symlinks is also caught.
3. The resolved path is matched against `sensitivePathPrefixes` — a list of
   root-owned system directories (`/etc`, `/var`, `/usr`, `/bin`, `/sys`,
   `/proc`, `/dev`, `/root`, `/Library/Keychains`, etc.). Any match returns an
   error and the process refuses to start.

### S-2 · Symlink Following — MEDIUM (Fixed)

**Problem:** `loadFiles()` used `os.ReadDir()` which calls `os.Stat()` internally
and follows symlinks. A symlink inside the custom audio directory pointing to a
sensitive file (e.g. `/etc/passwd`) would be silently opened as root.

**Fix:** `loadFiles()` now calls `os.Lstat()` on every candidate entry. Any
entry whose `Mode()` has `os.ModeSymlink` set is skipped with a warning printed
to stderr. Non-regular files (devices, named pipes, etc.) are also skipped.

### S-3 · Unsafe Path Construction — MEDIUM (Fixed)

**Problem:** `loadFiles()` constructed file paths via string concatenation
(`sp.dir + "/" + entry.Name()`). This is fragile and bypasses OS-level path
normalisation.

**Fix:** All path construction now uses `filepath.Join()`, which is
platform-correct and normalises separators and `.`/`..` components.

### S-4 · JSON Error Echo — LOW (Fixed)

**Problem:** The stdin command handler echoed raw error strings (including
user-supplied content) back to the caller:

```go
fmt.Fprintf(w, `{"error":"invalid command: %s"}`, err.Error())
fmt.Fprintf(w, `{"error":"unknown command: %s"}`, cmd.Cmd)
```

This could leak internal error detail or be used to inject content into the
JSON stream.

**Fix:** Both responses now use fixed strings:

```go
{"error":"invalid command format"}
{"error":"unknown command"}
```

---

## No-Issue Areas

### S-5 · Data Exfiltration / Network Access

A full review of `main.go` and all 23 direct and transitive dependencies
confirms:

- **No `net`, `net/http`, `net/rpc`, or similar network packages are imported**
  anywhere in the dependency graph that is reachable from the running binary.
- No DNS lookups, HTTP requests, or socket connections are made at runtime.
- All audio assets are compiled into the binary via `//go:embed`; no assets are
  downloaded at runtime.
- No telemetry, analytics, or crash-reporting SDKs (Sentry, Datadog, Segment,
  Mixpanel, etc.) appear in `go.sum`.

**Conclusion:** `spank` does not exfiltrate any data.

### S-6 · Command Injection

- `os/exec` is not imported; no subprocesses are spawned.
- `syscall` is used only for `SIGINT`/`SIGTERM` signal constants.
- No shell command construction or `eval`-equivalent calls exist.

### S-7 · Dependency Telemetry

All dependencies serve clearly scoped purposes (UI rendering, audio decoding,
CLI argument parsing, accelerometer access). None of these packages include
telemetry or analytics functionality.

---

## Threat Model

| Asset | Threat | Mitigation |
|-------|--------|-----------|
| System files (running as root) | Path traversal via `--custom` / `--custom-files` | `validateCustomPath` / `validateCustomFile` + sensitive-prefix blocklist |
| System files (running as root) | Symlink in custom audio directory | `os.Lstat()` + symlink rejection in `loadFiles()` |
| User privacy | Network exfiltration | No network packages imported |
| stdout integrity | JSON error injection via user-controlled input | Fixed error messages |

---

## Responsible Disclosure

If you discover a security issue in `spank`, please open a GitHub issue with
the `security` label or contact the maintainer directly before public
disclosure.
