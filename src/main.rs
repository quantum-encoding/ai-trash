//! trash — move files and directories to the system trash.
//!
//! A safe alternative to `rm` that uses the OS-native trash:
//!   - macOS: Finder Trash (recoverable via Put Back)
//!   - Windows: Recycle Bin
//!   - Linux: freedesktop.org trash specification
//!
//! Subcommands:
//!   trash <path> [path...]       — send files/dirs to trash
//!   trash list [--older <age>]   — list trashed items
//!   trash size [--bytes]         — show trash size
//!   trash empty [--older <age>]  — empty trash
//!   trash restore <pattern>      — restore from trash
//!
//! Designed for use with Claude Code and other AI agents where `rm -rf`
//! is blocked by deny policies but safe deletion should be allowed.

#![allow(dead_code, unused_imports)]

use std::ffi::CString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

// ── libc wrappers for macOS TCC bypass ─────────────────────────────
// macOS TCC blocks std::fs operations on ~/.Trash/ but libc calls work
// when our process has the right entitlements (e.g. linked Foundation).

unsafe extern "C" {
    fn rename(old: *const i8, new: *const i8) -> i32;
    fn unlink(path: *const i8) -> i32;
    fn rmdir(path: *const i8) -> i32;
}

fn libc_rename(from: &Path, to: &Path) -> io::Result<()> {
    let from_c = path_to_cstring(from)?;
    let to_c = path_to_cstring(to)?;
    if unsafe { rename(from_c.as_ptr(), to_c.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn libc_remove(path: &Path) -> io::Result<()> {
    let path_c = path_to_cstring(path)?;
    if unsafe { unlink(path_c.as_ptr()) } == 0 {
        return Ok(());
    }
    // If unlink fails (might be a directory), try rmdir
    if unsafe { rmdir(path_c.as_ptr()) } == 0 {
        return Ok(());
    }
    // Non-empty directory — recurse
    if path.is_dir() {
        for entry in fs::read_dir(path).into_iter().flatten().flatten() {
            libc_remove(&entry.path()).ok();
        }
        let path_c = path_to_cstring(path)?;
        if unsafe { rmdir(path_c.as_ptr()) } == 0 {
            return Ok(());
        }
    }
    Err(io::Error::last_os_error())
}

fn path_to_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.to_str().ok_or_else(|| io::Error::other("invalid path"))?)
        .map_err(|_| io::Error::other("path contains null"))
}

// ── Platform helpers ────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn trash_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".Trash")
}

#[cfg(target_os = "linux")]
fn trash_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".local/share/Trash/files")
}

#[cfg(target_os = "macos")]
fn info_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".Trash/.trash-metadata")
}

#[cfg(target_os = "linux")]
fn info_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".local/share/Trash/info")
}

// ── Trash entry ─────────────────────────────────────────────────────

struct TrashEntry {
    trash_filename: String,
    original_path: String,
    deletion_date: String,
    deletion_time: Option<SystemTime>,
    exists_in_trash: bool,
}

// ── .trashinfo reading ──────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
fn read_trash_info(path: &Path) -> Option<TrashEntry> {
    let content = fs::read_to_string(path).ok()?;
    let mut original_path = String::new();
    let mut deletion_date = String::new();

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("Path=") {
            // Linux trashinfo uses percent-encoding
            original_path = percent_decode(val);
        } else if let Some(val) = line.strip_prefix("DeletionDate=") {
            deletion_date = val.to_string();
        }
    }
    if original_path.is_empty() {
        return None;
    }

    let trash_filename = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let deletion_time = parse_iso_datetime(&deletion_date);
    let exists_in_trash = trash_dir().join(&trash_filename).exists();

    Some(TrashEntry {
        trash_filename,
        original_path,
        deletion_date,
        deletion_time,
        exists_in_trash,
    })
}

/// Decode percent-encoded strings (freedesktop trashinfo uses this).
#[cfg(not(target_os = "windows"))]
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(val) = u8::from_str_radix(
                &String::from_utf8_lossy(&bytes[i + 1..i + 3]),
                16,
            ) {
                out.push(val);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Parse "2026-03-31T14:30:22" to SystemTime (UTC, best-effort).
#[cfg(not(target_os = "windows"))]
fn parse_iso_datetime(s: &str) -> Option<SystemTime> {
    // Format: YYYY-MM-DDTHH:MM:SS
    let s = s.trim();
    if s.len() < 19 {
        return None;
    }
    let year: u64 = s[0..4].parse().ok()?;
    let month: u64 = s[5..7].parse().ok()?;
    let day: u64 = s[8..10].parse().ok()?;
    let hour: u64 = s[11..13].parse().ok()?;
    let min: u64 = s[14..16].parse().ok()?;
    let sec: u64 = s[17..19].parse().ok()?;

    // Approximate: days from epoch to date
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    let month_days = [31, if is_leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 0..(month.saturating_sub(1) as usize) {
        if m < 12 {
            days += month_days[m];
        }
    }
    days += day.saturating_sub(1);
    let secs = days * 86400 + hour * 3600 + min * 60 + sec;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

#[cfg(not(target_os = "windows"))]
fn is_leap(y: u64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

// ── .trashinfo writing (macOS only — Linux handled by trash crate) ──

#[cfg(target_os = "macos")]
fn write_trash_info(trash_filename: &str, original_path: &Path) -> io::Result<()> {
    let dir = info_dir();
    fs::create_dir_all(&dir)?;

    let now = now_iso();
    let content = format!(
        "[Trash Info]\nPath={}\nDeletionDate={}\n",
        original_path.display(),
        now,
    );

    let info_path = dir.join(format!("{}.trashinfo", trash_filename));
    fs::write(info_path, content)
}

/// Current local time as ISO string (best-effort, no TZ crate).
#[cfg(target_os = "macos")]
fn now_iso() -> String {
    // Use system `date` for correct local time without extra deps
    let output = std::process::Command::new("date")
        .arg("+%Y-%m-%dT%H:%M:%S")
        .output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => {
            // Fallback: seconds since epoch formatted roughly
            let d = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default();
            format!("epoch+{}", d.as_secs())
        }
    }
}

// ── Age parsing ─────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
fn parse_age(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, unit) = if s.as_bytes().last()?.is_ascii_alphabetic() {
        (&s[..s.len() - 1], s.as_bytes()[s.len() - 1])
    } else {
        (s, b'd') // default to days
    };
    let n: u64 = num_str.parse().ok()?;
    let secs = match unit {
        b's' => n,
        b'm' => n * 60,
        b'h' => n * 3600,
        b'd' => n * 86400,
        b'w' => n * 604800,
        b'M' => n * 2592000, // 30 days
        b'y' => n * 31536000,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

// ── Human-readable size ─────────────────────────────────────────────

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    for &unit in UNITS {
        if size < 1024.0 || unit == "TiB" {
            return if unit == "B" {
                format!("{} {}", bytes, unit)
            } else {
                format!("{:.1} {}", size, unit)
            };
        }
        size /= 1024.0;
    }
    format!("{} B", bytes)
}

// ── Directory size ──────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
fn dir_size(path: &Path) -> u64 {
    if path.is_file() || path.is_symlink() {
        return path.metadata().map(|m| m.len()).unwrap_or(0);
    }
    let mut total: u64 = 0;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() && !p.is_symlink() {
                total += dir_size(&p);
            } else {
                total += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    total
}

// ── Collect all trash entries ───────────────────────────────────────

#[cfg(not(target_os = "windows"))]
fn collect_entries() -> Vec<TrashEntry> {
    let info = info_dir();
    let mut entries = Vec::new();
    if let Ok(dir) = fs::read_dir(&info) {
        for entry in dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("trashinfo") {
                if let Some(te) = read_trash_info(&path) {
                    entries.push(te);
                }
            }
        }
    }
    // Also find untracked files in trash_dir (trashed externally)
    let tdir = trash_dir();
    if let Ok(dir) = fs::read_dir(&tdir) {
        for entry in dir.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            // Skip hidden metadata dir and .DS_Store
            if fname == ".trash-metadata" || fname == ".DS_Store" {
                continue;
            }
            let tracked = entries.iter().any(|e| e.trash_filename == fname);
            if !tracked {
                entries.push(TrashEntry {
                    trash_filename: fname,
                    original_path: String::new(),
                    deletion_date: String::new(),
                    deletion_time: None,
                    exists_in_trash: true,
                });
            }
        }
    }
    // Sort by date descending (newest first), untracked at end
    entries.sort_by(|a, b| b.deletion_date.cmp(&a.deletion_date));
    entries
}

// ── JSON escaping ───────────────────────────────────────────────────

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

// ── TTY check ───────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
fn is_tty() -> bool {
    unsafe { libc_isatty(0) != 0 }
}

#[cfg(not(target_os = "windows"))]
unsafe extern "C" {
    #[link_name = "isatty"]
    fn libc_isatty(fd: i32) -> i32;
}

// ── Subcommand: list ────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
fn cmd_list(args: &[String]) -> ExitCode {
    let mut older_than: Option<Duration> = None;
    let mut project_filter = false;
    let mut json_output = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--older" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("trash list: --older requires an age (e.g. 7d)");
                    return ExitCode::from(1);
                }
                match parse_age(&args[i]) {
                    Some(d) => older_than = Some(d),
                    None => {
                        eprintln!("trash list: invalid age '{}'", args[i]);
                        return ExitCode::from(1);
                    }
                }
            }
            "--project" => project_filter = true,
            "--json" => json_output = true,
            other => {
                eprintln!("trash list: unknown option '{}'", other);
                return ExitCode::from(1);
            }
        }
        i += 1;
    }

    let entries = collect_entries();
    let now = SystemTime::now();

    // Current working directory for --project filter
    let cwd = std::env::current_dir().unwrap_or_default();
    let cwd_str = cwd.to_string_lossy().to_string();

    let filtered: Vec<&TrashEntry> = entries
        .iter()
        .filter(|e| {
            if let Some(max_age) = older_than {
                if let Some(dt) = e.deletion_time {
                    if let Ok(age) = now.duration_since(dt) {
                        if age < max_age {
                            return false;
                        }
                    }
                } else {
                    // No date info — can't filter by age, include it
                }
            }
            if project_filter && !e.original_path.starts_with(&cwd_str) {
                return false;
            }
            true
        })
        .collect();

    if json_output {
        print!("[");
        for (idx, e) in filtered.iter().enumerate() {
            if idx > 0 {
                print!(",");
            }
            let path_display = if e.original_path.is_empty() {
                "(trashed externally)"
            } else {
                &e.original_path
            };
            print!(
                "\n  {{\"name\":\"{}\",\"path\":\"{}\",\"date\":\"{}\",\"in_trash\":{}}}",
                json_escape(&e.trash_filename),
                json_escape(path_display),
                json_escape(&e.deletion_date),
                e.exists_in_trash,
            );
        }
        println!("\n]");
    } else {
        if filtered.is_empty() {
            println!("Trash is empty.");
            return ExitCode::SUCCESS;
        }
        // Tabular: DATE  ORIGINAL_PATH
        for e in &filtered {
            let date = if e.deletion_date.is_empty() {
                "unknown     ".to_string()
            } else {
                // Pad or truncate to 19 chars
                format!("{:<19}", &e.deletion_date)
            };
            let path = if e.original_path.is_empty() {
                format!("{} (trashed externally)", e.trash_filename)
            } else {
                e.original_path.clone()
            };
            let marker = if !e.exists_in_trash { " [missing]" } else { "" };
            println!("{}  {}{}", date, path, marker);
        }
    }

    ExitCode::SUCCESS
}

// ── Subcommand: size ────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
fn cmd_size(args: &[String]) -> ExitCode {
    let show_bytes = args.iter().any(|a| a == "--bytes");

    let tdir = trash_dir();
    if !tdir.exists() {
        if show_bytes {
            println!("0");
        } else {
            println!("Trash is empty (0 B)");
        }
        return ExitCode::SUCCESS;
    }

    let total = dir_size(&tdir);
    if show_bytes {
        println!("{}", total);
    } else {
        println!("{}", human_size(total));
    }
    ExitCode::SUCCESS
}

// ── Subcommand: empty ───────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
fn cmd_empty(args: &[String]) -> ExitCode {
    let mut older_than: Option<Duration> = None;
    let mut confirmed = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--older" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("trash empty: --older requires an age (e.g. 7d)");
                    return ExitCode::from(1);
                }
                match parse_age(&args[i]) {
                    Some(d) => older_than = Some(d),
                    None => {
                        eprintln!("trash empty: invalid age '{}'", args[i]);
                        return ExitCode::from(1);
                    }
                }
            }
            "--yes" | "-y" => confirmed = true,
            other => {
                eprintln!("trash empty: unknown option '{}'", other);
                return ExitCode::from(1);
            }
        }
        i += 1;
    }

    // Confirmation
    if !confirmed {
        if !is_tty() {
            eprintln!("trash empty: refusing to empty trash without --yes (not a TTY)");
            return ExitCode::from(1);
        }
        let msg = if older_than.is_some() {
            let age_str = &args[args.iter().position(|a| a == "--older").unwrap() + 1];
            format!("Empty trash items older than {}? [y/N] ", age_str)
        } else {
            "Empty ALL trash? This cannot be undone. [y/N] ".to_string()
        };
        eprint!("{}", msg);
        io::stderr().flush().ok();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return ExitCode::from(1);
        }
        let answer = input.trim().to_lowercase();
        if answer != "y" && answer != "yes" {
            eprintln!("Cancelled.");
            return ExitCode::from(1);
        }
    }

    let now = SystemTime::now();
    let tdir = trash_dir();
    let idir = info_dir();
    let mut removed = 0u64;
    let mut errors = 0u64;

    if let Some(max_age) = older_than {
        // Selective: delete only items older than max_age
        let entries = collect_entries();
        for entry in &entries {
            let should_delete = if let Some(dt) = entry.deletion_time {
                now.duration_since(dt).map(|a| a >= max_age).unwrap_or(false)
            } else {
                false // skip items without date info when filtering by age
            };
            if !should_delete {
                continue;
            }
            // Delete the file in trash
            let trash_path = tdir.join(&entry.trash_filename);
            if trash_path.exists() {
                if let Err(e) = libc_remove(&trash_path) {
                    eprintln!("trash empty: failed to remove {}: {}", trash_path.display(), e);
                    errors += 1;
                    continue;
                }
            }
            // Delete the .trashinfo
            let info_path = idir.join(format!("{}.trashinfo", entry.trash_filename));
            let _ = libc_remove(&info_path);
            removed += 1;
        }
    } else {
        // Full empty: remove everything in trash dir and info dir
        if let Ok(dir) = fs::read_dir(&tdir) {
            for entry in dir.flatten() {
                let p = entry.path();
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname == ".trash-metadata" {
                    continue; // we'll clear metadata separately
                }
                match libc_remove(&p) {
                    Ok(()) => removed += 1,
                    Err(e) => {
                        eprintln!("trash empty: failed to remove {}: {}", p.display(), e);
                        errors += 1;
                    }
                }
            }
        }
        // Clear all metadata
        if let Ok(dir) = fs::read_dir(&idir) {
            for entry in dir.flatten() {
                let _ = libc_remove(&entry.path());
            }
        }
    }

    // Clean up orphaned .trashinfo (metadata with no corresponding file)
    if let Ok(dir) = fs::read_dir(&idir) {
        for entry in dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("trashinfo") {
                let stem = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
                if !tdir.join(&stem).exists() {
                    let _ = libc_remove(&path);
                }
            }
        }
    }

    if errors > 0 {
        eprintln!("Removed {} items ({} errors)", removed, errors);
        ExitCode::from(1)
    } else {
        println!("Removed {} items", removed);
        ExitCode::SUCCESS
    }
}

// ── Subcommand: restore ─────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
fn cmd_restore(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("trash restore: requires a pattern");
        return ExitCode::from(1);
    }

    let mut pattern = String::new();
    let mut restore_to: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--to" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("trash restore: --to requires a path");
                    return ExitCode::from(1);
                }
                restore_to = Some(args[i].clone());
            }
            s if s.starts_with('-') => {
                eprintln!("trash restore: unknown option '{}'", s);
                return ExitCode::from(1);
            }
            _ => {
                if pattern.is_empty() {
                    pattern = args[i].clone();
                } else {
                    eprintln!("trash restore: unexpected argument '{}'", args[i]);
                    return ExitCode::from(1);
                }
            }
        }
        i += 1;
    }

    if pattern.is_empty() {
        eprintln!("trash restore: requires a pattern");
        return ExitCode::from(1);
    }

    let entries = collect_entries();

    // Match pattern against original paths and trash filenames
    let matches: Vec<&TrashEntry> = entries
        .iter()
        .filter(|e| {
            if !e.exists_in_trash {
                return false;
            }
            // Match against original path (contains)
            if !e.original_path.is_empty() && e.original_path.contains(&pattern) {
                return true;
            }
            // Match against trash filename
            if e.trash_filename.contains(&pattern) {
                return true;
            }
            false
        })
        .collect();

    if matches.is_empty() {
        eprintln!("trash restore: no match for '{}'", pattern);
        return ExitCode::from(1);
    }

    let chosen = if matches.len() == 1 {
        matches[0]
    } else {
        // Multiple matches — prompt user
        if !is_tty() {
            eprintln!("trash restore: multiple matches, use more specific pattern or run interactively:");
            for m in &matches {
                let path = if m.original_path.is_empty() {
                    &m.trash_filename
                } else {
                    &m.original_path
                };
                eprintln!("  {}", path);
            }
            return ExitCode::from(1);
        }
        eprintln!("Multiple matches:");
        for (idx, m) in matches.iter().enumerate() {
            let path = if m.original_path.is_empty() {
                format!("{} (no original path)", m.trash_filename)
            } else {
                format!("{} [{}]", m.original_path, m.deletion_date)
            };
            eprintln!("  {}: {}", idx + 1, path);
        }
        eprint!("Select [1-{}]: ", matches.len());
        io::stderr().flush().ok();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return ExitCode::from(1);
        }
        let choice: usize = match input.trim().parse::<usize>() {
            Ok(n) if n >= 1 && n <= matches.len() => n - 1,
            _ => {
                eprintln!("Invalid selection.");
                return ExitCode::from(1);
            }
        };
        matches[choice]
    };

    // Determine target path
    let target = if let Some(ref to) = restore_to {
        PathBuf::from(to)
    } else if !chosen.original_path.is_empty() {
        PathBuf::from(&chosen.original_path)
    } else {
        eprintln!(
            "trash restore: no original path for '{}' — use --to <path>",
            chosen.trash_filename
        );
        return ExitCode::from(1);
    };

    // Check target doesn't exist
    if target.exists() {
        eprintln!("trash restore: target already exists: {}", target.display());
        return ExitCode::from(1);
    }

    // Create parent dirs
    if let Some(parent) = target.parent() {
        if !parent.exists() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("trash restore: cannot create {}: {}", parent.display(), e);
                return ExitCode::from(1);
            }
        }
    }

    // Move from trash back
    let trash_path = trash_dir().join(&chosen.trash_filename);
    if let Err(e) = libc_rename(&trash_path, &target) {
        eprintln!(
            "trash restore: failed to move {} -> {}: {}",
            trash_path.display(),
            target.display(),
            e
        );
        if cfg!(target_os = "macos") && e.raw_os_error() == Some(1) {
            eprintln!("hint: grant Full Disk Access to your terminal app in");
            eprintln!("  System Settings > Privacy & Security > Full Disk Access");
        }
        return ExitCode::from(1);
    }

    // Delete .trashinfo
    let info_path = info_dir().join(format!("{}.trashinfo", chosen.trash_filename));
    let _ = libc_remove(&info_path);

    println!("Restored: {} -> {}", chosen.trash_filename, target.display());
    ExitCode::SUCCESS
}

// ── Windows stubs ───────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn cmd_list(_args: &[String]) -> ExitCode {
    eprintln!("trash list: subcommand not yet supported on Windows");
    ExitCode::from(1)
}

#[cfg(target_os = "windows")]
fn cmd_size(_args: &[String]) -> ExitCode {
    eprintln!("trash size: subcommand not yet supported on Windows");
    ExitCode::from(1)
}

#[cfg(target_os = "windows")]
fn cmd_empty(_args: &[String]) -> ExitCode {
    eprintln!("trash empty: subcommand not yet supported on Windows");
    ExitCode::from(1)
}

#[cfg(target_os = "windows")]
fn cmd_restore(_args: &[String]) -> ExitCode {
    eprintln!("trash restore: subcommand not yet supported on Windows");
    ExitCode::from(1)
}

// ── Metadata snapshot + write (macOS) ───────────────────────────────

#[cfg(target_os = "macos")]
fn snapshot_trash_dir() -> std::collections::HashSet<String> {
    let tdir = trash_dir();
    let mut set = std::collections::HashSet::new();
    if let Ok(dir) = fs::read_dir(&tdir) {
        for entry in dir.flatten() {
            set.insert(entry.file_name().to_string_lossy().to_string());
        }
    }
    set
}

#[cfg(target_os = "macos")]
fn find_new_trash_entry(
    before: &std::collections::HashSet<String>,
    expected_name: &str,
) -> Option<String> {
    let tdir = trash_dir();
    // Check expected name first
    if !before.contains(expected_name) && tdir.join(expected_name).exists() {
        return Some(expected_name.to_string());
    }
    // Scan for any new entry (collision rename)
    if let Ok(dir) = fs::read_dir(&tdir) {
        for entry in dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !before.contains(&name) && name != ".trash-metadata" && name != ".DS_Store" {
                // Heuristic: should start with or contain the expected base name
                let stem = Path::new(expected_name)
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy();
                if name.contains(stem.as_ref()) {
                    return Some(name);
                }
            }
        }
    }
    // Fallback: any new file
    if let Ok(dir) = fs::read_dir(&tdir) {
        for entry in dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !before.contains(&name) && name != ".trash-metadata" && name != ".DS_Store" {
                return Some(name);
            }
        }
    }
    None
}

// ── Main ────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_help();
        return if args.is_empty() { ExitCode::from(1) } else { ExitCode::SUCCESS };
    }

    if args[0] == "--version" || args[0] == "-V" {
        println!("trash {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    // ── Subcommand dispatch ──────────────────────────────────────
    // Only if args[0] is a bare subcommand name (not a path that happens
    // to match). `trash ./list` or `trash -- list` fall through to delete.
    if !args[0].starts_with('-') && !args[0].starts_with('.') && !args[0].starts_with('/') {
        match args[0].as_str() {
            "list" => return cmd_list(&args[1..]),
            "size" => return cmd_size(&args[1..]),
            "empty" => return cmd_empty(&args[1..]),
            "restore" => return cmd_restore(&args[1..]),
            _ => {}
        }
    }

    // ── Existing trash-files logic ───────────────────────────────
    let mut dry_run = false;
    let mut verbose = false;
    let mut force = false;
    let mut paths: Vec<PathBuf> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-n" | "--dry-run" => dry_run = true,
            "-v" | "--verbose" => verbose = true,
            "-f" | "--force" => force = true,
            "-r" | "-rf" | "-R" => {} // accept and ignore — directories are always handled
            "--" => {
                // everything after -- is a path
                paths.extend(args[i + 1..].iter().map(PathBuf::from));
                break;
            }
            s if s.starts_with('-') && !s.starts_with("--") && s.len() > 1 => {
                // combined flags like -nv, -vf, -nvf
                for c in s[1..].chars() {
                    match c {
                        'n' => dry_run = true,
                        'v' => verbose = true,
                        'f' => force = true,
                        'r' | 'R' => {} // ignored — dirs always work
                        _ => {
                            eprintln!("trash: unknown flag '-{c}'");
                            return ExitCode::from(1);
                        }
                    }
                }
            }
            _ => paths.push(PathBuf::from(&args[i])),
        }
        i += 1;
    }

    if paths.is_empty() {
        eprintln!("trash: no paths specified");
        return ExitCode::from(1);
    }

    let mut errors = 0;

    for path in &paths {
        if !path.exists() {
            if force {
                if verbose {
                    eprintln!("trash: skipping (not found): {}", path.display());
                }
                continue;
            }
            eprintln!("trash: not found: {}", path.display());
            errors += 1;
            continue;
        }

        let canonical = match path.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("trash: cannot resolve {}: {e}", path.display());
                errors += 1;
                continue;
            }
        };

        if dry_run {
            let kind = if canonical.is_dir() { "dir " } else { "file" };
            println!("would trash {kind}: {}", canonical.display());
            continue;
        }

        // ── macOS: snapshot before delete, write metadata after ──
        #[cfg(target_os = "macos")]
        let before_snapshot = snapshot_trash_dir();
        #[cfg(target_os = "macos")]
        let expected_name = canonical
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        match trash::delete(&canonical) {
            Ok(()) => {
                if verbose {
                    println!("trashed: {}", canonical.display());
                }
                // Write .trashinfo on macOS
                #[cfg(target_os = "macos")]
                {
                    if let Some(trash_name) =
                        find_new_trash_entry(&before_snapshot, &expected_name)
                    {
                        if let Err(e) = write_trash_info(&trash_name, &canonical) {
                            if verbose {
                                eprintln!(
                                    "trash: warning: failed to write metadata for {}: {}",
                                    trash_name, e
                                );
                            }
                        }
                    } else if verbose {
                        eprintln!(
                            "trash: warning: could not find trash entry for {}",
                            canonical.display()
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("trash: failed to trash {}: {e}", canonical.display());
                errors += 1;
            }
        }
    }

    if errors > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

// ── Help ────────────────────────────────────────────────────────────

fn print_help() {
    println!(
        "\
trash — move files and directories to the system trash

USAGE:
    trash [OPTIONS] <path>...
    trash list [--older <age>] [--project] [--json]
    trash size [--bytes]
    trash empty [--older <age>] [--yes]
    trash restore <pattern> [--to <path>]

OPTIONS:
    -n, --dry-run   Show what would be trashed without doing it
    -v, --verbose   Print each path as it is trashed
    -f, --force     Ignore missing files (no error)
    -r              Accepted for rm compatibility (directories always work)
    -h, --help      Show this help
    -V, --version   Show version

SUBCOMMANDS:
    list            List items in trash
      --older <age>   Filter to items older than age (e.g. 7d, 2w, 1M)
      --project       Only items originally under current directory
      --json          Output as JSON array

    size            Show total trash size
      --bytes         Show exact byte count

    empty           Empty the trash
      --older <age>   Only remove items older than age
      --yes, -y       Skip confirmation prompt

    restore         Restore item from trash
      <pattern>       Match against original path or trash filename
      --to <path>     Restore to specific path (required if no metadata)

AGE UNITS:
    s=seconds  m=minutes  h=hours  d=days  w=weeks  M=months  y=years

EXAMPLES:
    trash file.txt                  # trash a file
    trash -v src/old/ tmp/*.log     # trash dir + glob, verbose
    trash -nf build/ dist/          # dry-run, skip missing
    trash -- -weird-filename        # path starting with dash
    trash list                      # show trashed items
    trash list --older 30d          # items older than 30 days
    trash size                      # human-readable trash size
    trash empty --older 7d --yes    # delete items older than 7 days
    trash restore myfile.rs         # restore matching item
    trash restore src/ --to ./old/  # restore to specific location

PLATFORMS:
    macOS    Finder Trash (with metadata tracking)
    Windows  Recycle Bin (subcommands not yet supported)
    Linux    freedesktop.org trash spec (~/.local/share/Trash)

Designed for Claude Code: block `rm` in deny policies, allow `trash`.
https://github.com/quantum-encoding/ai-trash"
    );
}
