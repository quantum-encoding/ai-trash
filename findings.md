# ai-trash — Red-Team Audit Findings

Target: `src/main.rs` @ `74f39cd` (master), single bin `trash`, deps: `trash = "5"`.
Scope: unsafe / overflow / Command::new / path TOCTOU / deserialization / panic / FS-deletion symlink & race / escape-outside-trash.
Scanner: `qai security` (rate-limited on CVE feed; AST pass clean) + manual review.

---

## H-1 — Arbitrary file overwrite via crafted `.trashinfo` on `restore`  [CWE-22 / CWE-732]

**File:** `src/main.rs:113-146`, `:150-169`, `:769-811`
**Severity:** High (local arbitrary write)

`read_trash_info` parses `Path=` from a `.trashinfo` file with **zero validation** and percent-decodes it. `cmd_restore` then does:

```rust
let target = if let Some(ref to) = restore_to { ... }
             else if !chosen.original_path.is_empty() {
                 PathBuf::from(&chosen.original_path)   // attacker-controlled
             } else { ... };
if target.exists() { /* fails closed */ }              // see H-3 for bypass
if let Some(parent) = target.parent() {
    if !parent.exists() { fs::create_dir_all(parent)?; }   // creates anywhere
}
libc_rename(&trash_path, &target)?;                    // moves trashed bytes to target
```

**Exploit.** Drop a file into `~/.local/share/Trash/info/owned.trashinfo` (Linux) or `~/.Trash/.trash-metadata/owned.trashinfo` (macOS) containing:

```
[Trash Info]
Path=%2FUsers%2Fvictim%2F.ssh%2Fauthorized_keys
DeletionDate=2026-04-28T10:00:00
```

with the corresponding payload at `~/.Trash/owned`. When the user runs `trash restore owned`, the payload is renamed onto `~/.ssh/authorized_keys`. `fs::create_dir_all(parent)` happily fabricates missing directories along the way.

**Threat model.** Anything with user-level write to the trash metadata dir — a sandboxed app without TCC (macOS), a confined Snap/Flatpak, a process running as the same UID, or any earlier file-write primitive — escalates to "rename-anywhere-the-user-can-write" the next time the user types `trash restore <pat>`. On macOS, `~/.Trash` *is* TCC-protected against arbitrary apps, but this binary explicitly bypasses TCC via libc, and any other already-Full-Disk-Access tool can plant the file.

**Fix.**
- Reject `Path=` values that are not absolute, contain `..` after canonicalization of the parent, or escape the user's HOME.
- Refuse to restore if `target` resolves outside the original trash session's expected roots.
- Open the destination with `O_NOFOLLOW | O_CREAT | O_EXCL` and write+rename, or use `renameatx_np(RENAME_EXCL)` on macOS / `renameat2(RENAME_NOREPLACE)` on Linux to make existence-check atomic with the rename.

---

## H-2 — Symlink traversal on empty / age-empty: deletes files outside trash  [CWE-59 / CWE-61]

**File:** `src/main.rs:47-67`
**Severity:** High (local arbitrary file deletion)

`libc_remove` falls back to a recursive walk gated by `path.is_dir()` — which **follows symlinks**:

```rust
fn libc_remove(path: &Path) -> io::Result<()> {
    ...
    if unsafe { unlink(path_c.as_ptr()) } == 0 { return Ok(()); }
    if unsafe { rmdir(path_c.as_ptr()) } == 0 { return Ok(()); }
    if path.is_dir() {                              // ← follows symlink
        for entry in fs::read_dir(path).into_iter().flatten().flatten() {
            libc_remove(&entry.path()).ok();        // entry.path() is parent/<name>
        }
        ...
    }
}
```

`unlink(2)` on a directory returns `EISDIR`/`EPERM`. `rmdir(2)` on a non-empty directory returns `ENOTEMPTY`. We then enter the "recurse" branch on **anything `is_dir()` resolves to a directory** — including a symlink to `/Users/victim/Documents/`. `fs::read_dir` follows the symlink, and `entry.path()` is `~/.Trash/badlink/<file>`, where the kernel resolves the symlink during `unlink` and removes the actual victim file.

**Exploit.** Plant `~/.Trash/badlink → /Users/victim/Documents` (any process running as the user can do this; same threat model as H-1). Run `trash empty --yes`. Every regular file under `Documents/` is deleted via path rewriting through the symlink.

**Variant.** The same pattern fires from `cmd_empty` lines 611-625 (full empty), and from the `--older` selective path at line 598.

**Fix.** Use `symlink_metadata()` not `is_dir()`:

```rust
let md = fs::symlink_metadata(path)?;
if md.file_type().is_symlink() { return Err(io::Error::other("symlink in trash")); }
if md.is_dir() { /* recurse */ }
```

Better: open the trash dir with `O_DIRECTORY|O_NOFOLLOW`, walk with `*at`-family syscalls (`unlinkat`, `fstatat(AT_SYMLINK_NOFOLLOW)`).

---

## H-3 — `target.exists()` → `rename` TOCTOU; rename silently overwrites  [CWE-367]

**File:** `src/main.rs:782-799`
**Severity:** Medium (combines with H-1 to defeat the existence guard)

```rust
if target.exists() {                               // T0: check
    return ExitCode::from(1);
}
...
libc_rename(&trash_path, &target)                  // T1: rename — overwrites silently
```

POSIX `rename(2)` atomically replaces an existing destination if it's a regular file (or empty dir matching dir-source). The `exists()` call also follows symlinks: a dangling symlink at `target` returns `false`, then `rename` overwrites whatever the parent symlink resolves to.

**Fix.** Use `linkat(AT_SYMLINK_FOLLOW = 0)` + `unlink`, or `renameatx_np(RENAME_EXCL)` (macOS 10.13+) / `renameat2(RENAME_NOREPLACE)` (Linux 3.15+).

---

## H-4 — `path.canonicalize()` causes `trash <symlink>` to trash the *target*  [CWE-59]

**File:** `src/main.rs:985`
**Severity:** Medium (footgun; semantic divergence from `rm`)

```rust
let canonical = match path.canonicalize() { ... };
...
trash::delete(&canonical)
```

`canonicalize` resolves all symlinks. So `trash mylink` (where `mylink → /important/data/`) trashes `/important/data/`, not the symlink. `rm mylink` removes only the symlink. Users coming from `rm` semantics — which the README sells as "safe alternative to `rm`" — will eventually destroy the wrong thing. Worse: the trashed item's `original_path` is the *resolved* target, so a later `restore` writes the data to a different filename than what the user typed.

**Fix.** Only canonicalize the parent directory; keep the leaf name as-is so symlinks at the leaf are passed straight to `trash::delete` (which on macOS preserves symlink semantics).

---

## M-1 — `Command::new("date")` PATH hijack  [CWE-426 / CWE-78]

**File:** `src/main.rs:228-242`
**Severity:** Low-Medium (env-dependent)

`now_iso()` shells out without an absolute path:

```rust
std::process::Command::new("date").arg("+%Y-%m-%dT%H:%M:%S").output()
```

If a process inherits a `PATH` containing an attacker-writable directory before `/bin`, `date` is hijacked. Output goes straight into the `.trashinfo` DeletionDate field, which is then read back by `read_trash_info` — log/metadata injection. More importantly the hijacked binary runs with the user's privileges every time something is trashed on macOS.

**Fix.** Use `/bin/date`, or kill the dependency entirely with a tiny inline UTC formatter (already half-built in `parse_iso_datetime` — invert it) — chrono is already pulled in transitively via `trash` (Cargo.lock contains `chrono`), so a real formatter is one dep-feature flip away.

---

## M-2 — Panic on non-char-boundary string slicing in `parse_iso_datetime`  [CWE-248]

**File:** `src/main.rs:173-200`
**Severity:** Low (DoS during `trash list`)

```rust
let year:  u64 = s[0..4].parse().ok()?;
let month: u64 = s[5..7].parse().ok()?;
...
```

A crafted `DeletionDate=żẐẑẓ-...` (multi-byte UTF-8) makes `&s[0..4]` panic at the string-boundary assertion. `s.len() < 19` checks **byte length**, so the guard passes. Net effect: any `trash list` run aborts because one poisoned `.trashinfo` exists. Not exploitable for code exec, but a pure DoS-by-metadata.

**Fix.** Use `s.as_bytes()` directly (data is ASCII by spec), or `s.get(0..4)` which returns `None` on a non-boundary instead of panicking.

---

## M-3 — `HOME=/tmp` fallback is predictable + multi-user writable  [CWE-377]

**File:** `src/main.rs:78, 84, 90, 96`
**Severity:** Low

```rust
let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
```

If `HOME` is unset (cron, systemd unit with `Environment=`, container without entrypoint), the trash falls through to `/tmp/.Trash` — a world-writable dir on standard Unix where any local user can pre-create the path as a symlink and weaponize H-1/H-2 against the next invocation. Refuse to run if HOME is absent or non-absolute.

---

## L-1 — `find_new_trash_entry` snapshot-diff race  [CWE-362]

**File:** `src/main.rs:850-897`
**Severity:** Low (metadata mismatch only)

Between `snapshot_trash_dir()` (line 1002) and `trash::delete()` (line 1010), any other process trashing into `~/.Trash` causes the diff to pick the *attacker's* file as "ours", and we then write our `.trashinfo` (with our `original_path`) for their file. Result: their file restores to our path on the next restore. Combined with H-1 and an attacker who wins the race, this is another arbitrary-write primitive — but the race window is small and same-UID-only, so I'm rating this Low.

---

## L-2 — TOCTOU between `canonicalize` and `trash::delete`  [CWE-367]

**File:** `src/main.rs:985-1010`
**Severity:** Low

Resolution of `path.canonicalize()` happens, then `trash::delete(&canonical)` re-walks. An attacker swapping the path for a symlink in between can change *what* is trashed. Standard FS-race; not specific to this app.

---

## L-3 — Recursion depth, no bound  [CWE-674]

**File:** `src/main.rs:47-67` (`libc_remove`), `:292-308` (`dir_size`)
**Severity:** Informational

Both recurse on directory depth. A trashed pathologically deep tree (or a symlink loop in the empty path — see H-2) blows the thread stack. Cap with iterative walk + visited-set, or `WalkDir::same_file_system(true)`.

---

## Clean

- No `unsafe` other than the libc FFI block (audited; CStrings are well-formed, no aliasing).
- No `Command` with shell-string concatenation.
- No deserialization (no serde, no JWT, no network).
- No XSS sinks.
- Integer math in `parse_iso_datetime` cannot overflow within u64 given the 4-digit-year slice.
- `json_escape` covers control chars, quotes, backslash — log/JSON injection through filenames is contained.
- Cargo.lock CVE lookup attempted via `qai security`; NVD/GitHub were rate-limited on the run, so deps were not enumerated against CVE feeds. Re-run with `NVD_API_KEY` + `GITHUB_TOKEN`. The dep tree (libc, trash, chrono, objc2-foundation, percent-encoding) has no currently-known unpatched advisories I'm aware of.

---

## Suggested fix order

1. **H-2** (symlink-traversal on empty) — biggest blast radius, easiest fix (`symlink_metadata`).
2. **H-1** (restore arbitrary write) — validate `Path=` against an allowlist.
3. **H-4** (canonicalize-on-trash) — unexpected semantics, file-loss bug for users.
4. **H-3** atomic rename, then **M-1** absolute path for `date`, then **M-2** safe slicing.

