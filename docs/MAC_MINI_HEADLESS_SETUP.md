# Mac Mini Setup (Headless Ghidra Farm)

This repo supports a "one binary per Ghidra process" workflow on Mac minis so you can run multiple agents concurrently with process-level isolation.

This setup does **not** require the GUI plugin. It uses:
- Ghidra's `support/analyzeHeadless`
- `ghidra_scripts/GhidraMCPHeadlessServer.java`
- `scripts/ghidra_farm.py`

## Prereqs

- macOS on the mini
- Python 3.10+ (for `scripts/ghidra_farm.py`)
- Ghidra 11.4.2 installed on the mini

### One-shot setup script (recommended)

This repo includes a bootstrap script that installs:
- JDK 21 (required for Ghidra 11.4.x)
- Python 3.12
- uv
- optionally, Ghidra 11.4.2 from a local zip or URL

See: `scripts/setup_mac.sh`

### Install Python 3.12 + uv (recommended)

Homebrew Python installs `python3.12` at:
- `/opt/homebrew/bin/python3.12`

It also provides unversioned shims (`python3`, `pip3`, etc.) under:
- `/opt/homebrew/opt/python@3.12/libexec/bin`

Recommended:

```bash
brew install python@3.12 uv
echo 'export PATH="/opt/homebrew/opt/python@3.12/libexec/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
python3 --version
uv --version
```

Optional (repo-local venv via uv):

```bash
cd ~/Github/GhidraMCP
uv venv --python /opt/homebrew/bin/python3.12
uv pip install -r requirements-dev.txt
uv run python scripts/ghidra_farm.py --help
```

### Install Ghidra 11.4.2

1. Download Ghidra 11.4.2 for macOS from https://ghidra-sre.org/ (or your internal mirror).
2. Unzip it somewhere stable, for example:
   - `/Applications/ghidra_11.4.2_PUBLIC/`
   - or `~/tools/ghidra_11.4.2_PUBLIC/`
3. Gatekeeper quarantine sometimes blocks execution after download. If `analyzeHeadless` fails with permission/quarantine errors:

```bash
xattr -dr com.apple.quarantine "/Applications/ghidra_11.4.2_PUBLIC"
```

4. Verify `analyzeHeadless` exists:

```bash
ls -la "/Applications/ghidra_11.4.2_PUBLIC/support/analyzeHeadless"
```

If you prefer to install from a zip automatically, use:

```bash
cd ~/Github/GhidraMCP
scripts/setup_mac.sh --install-brew --with-ghidra --ghidra-zip "/path/to/ghidra_11.4.2_PUBLIC_*.zip"
```

If you want to use the default official NSA GitHub release asset URL, you can omit `--ghidra-zip/--ghidra-url`:

```bash
cd ~/Github/GhidraMCP
scripts/setup_mac.sh --install-brew --with-ghidra --ghidra-dest-dir "$HOME/tools"
```

## Repo install on the mini

Clone or update your repo on the mini:

```bash
git clone <your-fork-or-origin> ~/Github/GhidraMCP
cd ~/Github/GhidraMCP
```

The launcher and headless script live in this repo:
- `scripts/ghidra_farm.py`
- `ghidra_scripts/GhidraMCPHeadlessServer.java`

## Do I need to install the GUI plugin?

No for the headless farm.

- The headless farm uses `analyzeHeadless` + `ghidra_scripts/GhidraMCPHeadlessServer.java` and does not require installing the GUI extension.
- If you also want the GUI plugin on your MacBook (interactive reversing), you install it via Ghidra UI: `File -> Install Extensions`.
  Rebuilding it is separate from the headless farm workflow (see `build.sh`).

## Job directory layout

Create a `jobs_root/` with one subdirectory per binary. Each job directory needs a `job.json`:

```
jobs_root/
  binA/
    job.json
    binary
  binB/
    job.json
    chall.exe
```

Minimal `job.json`:

```json
{
  "binary": "binary"
}
```

Recommended explicit port (easier to wire agents to fixed URLs):

```json
{
  "binary": "binary",
  "java_opts": ["-Xmx4g"],
  "bind_host": "127.0.0.1",
  "port": 18080,
  "analyze": true
}
```

## Analysis artifacts / per-job isolation

Each job directory gets its own dedicated Ghidra project directory:
- `project_dir` in `job.json` (default: `.ghidra_project` under the job directory)

That directory contains the Ghidra project database and analysis state for that one binary (the artifacts you want to persist after analysis).

## Start the farm

From the repo root on the mini:

```bash
python scripts/ghidra_farm.py "/path/to/jobs_root" \
  --ghidra-install-dir "/Applications/ghidra_11.4.2_PUBLIC" \
  --registry "/path/to/jobs_root/servers.json"
```

Per job directory, this will write:
- `server.json` (url, port, command, metadata)
- `ghidra_headless.pid`
- `ghidra_headless.log`

You can sanity-check one job with:

```bash
curl "http://127.0.0.1:18080/health"
curl "http://127.0.0.1:18080/get_program_name"
```

## Stop the farm

```bash
python scripts/ghidra_farm.py "/path/to/jobs_root" \
  --ghidra-install-dir "/Applications/ghidra_11.4.2_PUBLIC" \
  --stop
```

If you need to force-stop:

```bash
python scripts/ghidra_farm.py "/path/to/jobs_root" \
  --ghidra-install-dir "/Applications/ghidra_11.4.2_PUBLIC" \
  --stop --signal KILL
```

## Remote access (MacBook -> Mac mini)

The headless server has **no authentication**. Do not bind it to a public interface unless you put it behind a firewall/VPN.

Recommended:
- keep `bind_host: 127.0.0.1`
- use SSH port forwarding from your MacBook:

```bash
ssh -L 18080:127.0.0.1:18080 <user>@<mac-mini-hostname-or-ip>
```

Then point your MCP bridge at `http://127.0.0.1:18080/` on your MacBook.

## Updating the mini

When you update code in this repo (launcher or headless server script):

1. Stop running jobs:
   ```bash
   cd ~/Github/GhidraMCP
   python scripts/ghidra_farm.py "/path/to/jobs_root" \
     --ghidra-install-dir "/Applications/ghidra_11.4.2_PUBLIC" \
     --stop
   ```
2. Update repo:
   ```bash
   git pull
   ```
3. Start jobs again:
   ```bash
   python scripts/ghidra_farm.py "/path/to/jobs_root" \
     --ghidra-install-dir "/Applications/ghidra_11.4.2_PUBLIC" \
     --registry "/path/to/jobs_root/servers.json"
   ```

If you update Ghidra itself (e.g. reinstall 11.4.2), just change `--ghidra-install-dir`.

## Troubleshooting

- **Port already in use**
  - Set `port` in `job.json` to a different value, or omit it to auto-pick a free port.
- **Job won't start**
  - Check `ghidra_headless.log` in the job directory.
  - Confirm quarantine is cleared (see `xattr` step).
- **Out of memory / the mini slows to a crawl**
  - Reduce concurrency (fewer jobs at once), or reduce each job's `java_opts` heap size.
  - Example: set `java_opts` to `["-Xmx2g"]` for 4 jobs on a 16GB mini.
- **Binary path rejected**
  - `job.json` `binary` must be relative and must resolve under the job dir (intentional safety check).

