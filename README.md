# update-fastfetch

A small POSIX `sh` script that updates **Fastfetch** on Debian/Ubuntu-like systems by downloading the latest official `.deb` from GitHub Releases, **verifying its SHA-256 checksum**, and installing it via `dpkg`.

## What it does

- Detects your CPU architecture (`uname -m` → release asset token)
- Reads the installed Fastfetch version (or assumes `0.0.0` if not installed)
- Determines the latest release version
  - Uses the GitHub API when available
  - Falls back to a GitHub “latest release” redirect probe if the API is unavailable/rate-limited
- Downloads the matching `.deb` to `/tmp`
- **Verifies the downloaded file’s SHA-256** against the checksum listed in the upstream release notes
  - If a matching checksum cannot be found, the script **aborts** (fails closed)
- Installs the verified `.deb` with `dpkg`

## Requirements

- `curl`
- `awk`
- `grep`
- `dpkg`
- `sha256sum`
- `sudo` *(only required when not running as root)*

## Usage

```sh
update-fastfetch
```

### Flags (exactly 0 or 1 flag allowed)

This script is intentionally strict: **use at most one flag**. If you provide multiple flags, unknown options, or positional arguments, it exits with code `2`.

```sh
update-fastfetch --polyfilled
update-fastfetch --self-test
update-fastfetch --no-color
update-fastfetch --help
update-fastfetch --version
```

#### `--polyfilled`

Installs the *polyfilled* build (more portable), selecting:

- `fastfetch-linux-<arch>-polyfilled.deb`

instead of:

- `fastfetch-linux-<arch>.deb`

#### `--self-test`

Runs diagnostic checks and exits (no install). It prints **OK/WARN/ERROR for each check**, runs all checks (no fail-fast), and ends with a **colored summary line**.

Current checks:

- Required tools: `curl`, `awk`, `grep`, `dpkg`, `sha256sum` (and `sudo` if not running as root)
- Privilege mode: running as root vs needing `sudo`
- Can reach `https://github.com/`
- Can reach the GitHub API endpoint used for latest release *(warn-only; fallback exists)*
- Can reach the repo’s `releases/latest` endpoint

#### `--no-color` / `NO_COLOR`

Disables colored output.

- Flag: `update-fastfetch --no-color`
- Env var: `NO_COLOR=1 update-fastfetch`

## Exit codes

- `0` success / already up-to-date / self-test passed
- `1` fatal error (missing dependency, checksum missing/mismatch, failed self-test, etc.)
- `2` invalid arguments (unknown option, positional argument, or multiple flags)

## Installation

Example:

```sh
sudo install -m 0755 update-fastfetch /usr/local/bin/update-fastfetch
```

## Notes on security

This script downloads official prebuilt `.deb` assets from the upstream Fastfetch GitHub Releases page over HTTPS.

- It **verifies SHA-256** by scraping the upstream release notes for the checksum corresponding to the exact downloaded asset.
- If the checksum is missing or the release notes format changes such that the checksum cannot be found, the script **aborts** rather than installing an unchecked file.
- It does **not** verify signatures.

## License

MIT