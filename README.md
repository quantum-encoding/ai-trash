# trash-cli

Move files and directories to the system trash — a safe, recoverable alternative to `rm`.

**330KB** single binary. No dependencies. Cross-platform.

## Why

AI coding agents (Claude Code, Cursor, etc.) execute shell commands. A misplaced `rm -rf` is permanent and costly. The solution:

1. **Block** `rm` in your deny policy
2. **Allow** `trash` — files go to the OS trash, recoverable with undo

```
# Claude Code settings.json
{
  "permissions": {
    "deny": ["Bash(rm *)", "Bash(rm -rf *)"],
    "allow": ["Bash(trash *)"]
  }
}
```

## Install

### From source (any platform)
```bash
cargo install --git https://github.com/quantum-encoding/trash-cli
```

### Pre-built binaries
Download from [Releases](https://github.com/quantum-encoding/trash-cli/releases):
- `trash-macos-arm64` (Apple Silicon)
- `trash-macos-x64` (Intel Mac)
- `trash-linux-x64` (Linux x86_64)
- `trash-windows-x64.exe` (Windows)

### Homebrew (coming soon)
```bash
brew install quantum-encoding/tap/trash-cli
```

## Usage

```bash
trash file.txt                  # trash a file
trash -v src/old/ tmp/*.log     # trash dir + glob, verbose
trash -nf build/ dist/          # dry-run, skip missing
trash -- -weird-filename        # path starting with dash
```

### Options

| Flag | Description |
|------|-------------|
| `-n`, `--dry-run` | Show what would be trashed without doing it |
| `-v`, `--verbose` | Print each path as it is trashed |
| `-f`, `--force` | Ignore missing files (no error) |
| `-r` | Accepted for `rm` compatibility (directories always work) |

### Recovery

| Platform | How to recover |
|----------|---------------|
| macOS | Finder → Trash → right-click → Put Back (or ⌘Z) |
| Windows | Recycle Bin → right-click → Restore |
| Linux | Files app → Trash → Restore |

## How it works

Uses the [`trash`](https://crates.io/crates/trash) crate which calls OS-native APIs:

- **macOS**: `NSFileManager.trashItem` (same as Finder "Move to Trash")
- **Windows**: `IFileOperation` COM interface (same as Explorer delete)
- **Linux**: [freedesktop.org Trash spec](https://specifications.freedesktop.org/trash-spec/latest/) (`~/.local/share/Trash`)

## Claude Code integration

Add to your project's `CLAUDE.md`:

```markdown
## File deletion
Use `trash` instead of `rm` for all file deletions. The `trash` binary
moves files to the system trash (recoverable) instead of permanent deletion.
```

Or configure in `settings.json`:

```json
{
  "permissions": {
    "deny": ["Bash(rm *)", "Bash(rm -rf *)", "Bash(rmdir *)"],
    "allow": ["Bash(trash *)"]
  }
}
```

## License

MIT — [Quantum Encoding Ltd](https://quantumencoding.ai)
