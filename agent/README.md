# egress-agent

Linux-only Rust agent that captures outbound network egress using eBPF (via `bpftrace`), enriches events with process lineage from `/proc`, and writes a final run summary JSON file.

> PoC design goals: readable code, minimal dependencies, robust behavior (best-effort capture, never hard-fail your pipeline), and good logs.

## Requirements

- Linux host (target use-case: GitHub Actions runners)
- `bpftrace` installed and executable
- Privileges to attach eBPF probes (typically `sudo`)

On Ubuntu runners:

```sh
sudo apt-get update
sudo apt-get install -y bpftrace
```

## Build

```sh
cd agent
cargo build --release
```

## Usage

### Foreground capture (until interrupted)

```sh
./target/release/egress-agent --output run-summary.json
# stop with Ctrl+C (SIGINT) when done
```

### Background capture (recommended for CI)

```sh
sudo ./target/release/egress-agent --output run-summary.json >agent.out.log 2>agent.err.log &
AGENT_PID=$!

# ... run build/test steps ...

sudo kill -TERM "$AGENT_PID"
wait "$AGENT_PID" || true
```

## GitHub Actions runner notes

- Most GitHub-hosted Linux runners require `sudo` for eBPF attachment.
- Keep the step non-blocking for your job by using `continue-on-error: true` when experimenting.
- Typical pattern is to start the agent in background before job steps, then stop it at the end and upload `run-summary.json` (or send it to the control-plane).

Example pattern:

```yaml
- name: Start egress agent
  continue-on-error: true
  run: |
    sudo ./agent/target/release/egress-agent --output run-summary.json >agent.out.log 2>agent.err.log &
    echo $! > agent.pid

# ... regular job steps ...

- name: Stop egress agent
  if: always()
  continue-on-error: true
  run: |
    if [ -f agent.pid ]; then
      sudo kill -TERM "$(cat agent.pid)" || true
      wait "$(cat agent.pid)" || true
    fi
```

## Output

The summary JSON includes:

- metadata (timings, host, backend)
- all captured egress events
- per-event process lineage chain (root process -> leaf process)
- aggregated `process_lineage_tree` with direct and total egress counts
- error and drop counters

## Releasing

A GitHub workflow is provided at `.github/workflows/release-agent.yml`.

- Tag-based release: push a tag like `agent-v0.1.0`
- Manual release: run **Actions → Release egress agent** and provide `release_tag`

The workflow builds and publishes release assets for:
- Linux `amd64` (`x86_64-unknown-linux-gnu`)
- Linux `arm64` (`aarch64-unknown-linux-gnu`)

Each release includes:
- `egress-agent-linux-amd64.tar.gz`
- `egress-agent-linux-amd64.tar.gz.sha256`
- `egress-agent-linux-arm64.tar.gz`
- `egress-agent-linux-arm64.tar.gz.sha256`

## Notes

- Primary backend is a `bpftrace` script on `sys_enter_connect` (IPv4 + IPv6 best effort).
- Capture scope is **system-wide** (no PID filter), so newly launched container processes are observed as well.
- Logs are split by level: `INFO`/`DEBUG` to stdout, `WARN`/`ERROR` to stderr.
- The summary file is written on graceful shutdown/finish (handled termination signal).
- If the richer IPv4+IPv6 script fails to attach, the agent falls back to IPv4-only.
- If eBPF backend cannot start, the agent still exits successfully and writes a summary with errors.
- The agent avoids `panic!` and tries to keep running even under partial failures.
