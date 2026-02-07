# update-fastfetch

A small POSIX `sh` script that updates **Fastfetch** on Debian/Ubuntu-like systems by downloading the latest official `.deb` from GitHub Releases and installing it via `dpkg`.

## What it does

- Detects your CPU architecture (`uname -m` → release asset token)
- Reads the installed Fastfetch version (or assumes `0.0.0` if not installed)
- Determines the latest release version
  - Uses the GitHub API when available
  - Falls back to a GitHub “latest release” redirect probe if the API is unavailable/rate-limited
- Downloads the matching `.deb` to `/tmp` and installs it with `dpkg`

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
update-fastfetch --help
update-fastfetch --version
```

#### `--polyfilled`

Installs the *polyfilled* build (more portable), selecting:

- `fastfetch-linux-<arch>-polyfilled.deb`

instead of:

- `fastfetch-linux-<arch>.deb`

#### `--self-test`

Runs diagnostic checks and exits (no install). It prints **OK/WARN/ERROR for each check** and only fails at the end if any **ERROR** occurred.

Current checks:

- Required tools: `curl`, `awk`, `grep`, `dpkg`, `sha256sum` (and `sudo` if not running as root)
- Can reach `https://github.com/`
- Can reach the GitHub API endpoint used for latest release *(warn-only; fallback exists)*
- Can reach the repo’s `releases/latest` endpoint

## Exit codes

- `0` success / already up-to-date / self-test passed
- `1` fatal error (missing dependency, failed self-test, etc.)
- `2` invalid arguments (unknown option, positional argument, or multiple flags)

## Installation

Example:

```sh
sudo install -m 0755 update-fastfetch /usr/local/bin/update-fastfetch
```

## Notes on security

This script downloads official prebuilt `.deb` assets from the upstream Fastfetch GitHub Releases page over HTTPS.

- It verifies the downloaded .deb against the SHA-256 listed in the upstream release notes; if it can’t find a matching checksum, it aborts.
- It does **not** verify signatures.
- You are trusting the upstream release assets and your network’s TLS path.

## License

MIT
