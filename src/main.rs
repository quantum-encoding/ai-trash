//! trash — move files and directories to the system trash.
//!
//! A safe alternative to `rm` that uses the OS-native trash:
//!   - macOS: Finder Trash (recoverable via Put Back)
//!   - Windows: Recycle Bin
//!   - Linux: freedesktop.org trash specification
//!
//! Designed for use with Claude Code and other AI agents where `rm -rf`
//! is blocked by deny policies but safe deletion should be allowed.
//!
//! Usage:
//!   trash <path> [path...]
//!   trash -n <path>          # dry-run — show what would be trashed
//!   trash -v <path>          # verbose — print each file as it's trashed
//!   trash -f <path>          # force — don't error on missing files

use std::path::PathBuf;
use std::process::ExitCode;

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

        match trash::delete(&canonical) {
            Ok(()) => {
                if verbose {
                    println!("trashed: {}", canonical.display());
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

fn print_help() {
    println!(
        "\
trash — move files and directories to the system trash

USAGE:
    trash [OPTIONS] <path>...

OPTIONS:
    -n, --dry-run   Show what would be trashed without doing it
    -v, --verbose   Print each path as it is trashed
    -f, --force     Ignore missing files (no error)
    -r              Accepted for rm compatibility (directories always work)
    -h, --help      Show this help
    -V, --version   Show version

EXAMPLES:
    trash file.txt                  # trash a file
    trash -v src/old/ tmp/*.log     # trash dir + glob, verbose
    trash -nf build/ dist/          # dry-run, skip missing
    trash -- -weird-filename        # path starting with dash

PLATFORMS:
    macOS    Finder Trash (⌘Z to undo in Finder)
    Windows  Recycle Bin
    Linux    freedesktop.org trash spec (~/.local/share/Trash)

Designed for Claude Code: block `rm` in deny policies, allow `trash`.
https://github.com/quantum-encoding/ai-trash"
    );
}
