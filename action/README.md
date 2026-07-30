# GHApp egress monitor action

This JavaScript action starts the Rust egress agent in the background during the main step and, in the post step, stops it and uploads the generated summary JSON to the control-plane.

## Inputs

All inputs are optional.

- `control_plane_base_url`
  - default: `https://ghapp-control-plane-35h6b4wbbq-uc.a.run.app`
- `agent_version`
  - default: `latest`
  - set to a specific release tag to pin (example: `agent-v0.1.0`)

## Behavior

- Never calls `core.setFailed`.
- Logs errors/warnings and continues (fail-open behavior).
- Linux-only (no-op on non-Linux runners).
- Downloads the requested agent release asset (`agent_version`) for current Linux architecture from this action repository.
- Obtains GitHub OIDC token in post-step and uses `/runs/token` + `/runs` flow.

## Usage

```yaml
permissions:
  id-token: write

steps:
  - uses: actions/checkout@v7

  - name: Start egress monitor (main) and upload on post
    uses: nicolasparada/ghapp-demo@main

  # ... regular job steps ...
```

> `id-token: write` is required for OIDC token minting in the post-step.
