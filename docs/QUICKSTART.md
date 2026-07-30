# Quickstart

This is the document every release tarball ships (`docs/QUICKSTART.md`, alongside the
binary, `LICENSE`, and `README.md`). It gets a new user from nothing to a running proxy
with no package manager and no build step.

## Install

```sh
curl -fsSL https://github.com/ELares/IronTraffic/releases/latest/download/install.sh | sh
```

This downloads the tarball for your platform, verifies its checksum, and installs
`irontraffic` to `$HOME/.local/bin` (override with `--prefix`). See
`scripts/install.sh --help` and `docs/RELEASE.md` for what the checksum does and does
not prove, and for the four platforms this ships prebuilt binaries for. If your
platform is not one of them, build from source:

```sh
git clone https://github.com/ELares/IronTraffic.git
cd IronTraffic
cargo build --release -p irontraffic
```

## Check the install

```sh
irontraffic --version
```

## Write a configuration

IronTraffic reads one YAML (or JSON) document naming a listener, an upstream, and the
timeouts and shutdown behavior around them. Save this as `config.yaml`:

```yaml
apiVersion: irontraffic.io/v1
listeners:
  - name: web
    bind: "0.0.0.0:8080"
upstream:
  address: "127.0.0.1:9000"
timeouts:
  connect_ms: 2000
  idle_ms: 60000
  half_close_ms: 5000
shutdown:
  graceful_timeout_ms: 30000
  drain_jitter_ms: 250
```

This listens on port 8080 and forwards every connection to an upstream at
`127.0.0.1:9000`. Point `upstream.address` at whatever you are proxying to before
going further.

## Validate before you run anything

```sh
irontraffic validate --config config.yaml --print
```

Exit code 0 means the document is well formed and every value is in range; anything
else means it is not, and the diagnostics on stderr say which field and why. `--print`
writes the fully resolved document (every default filled in) to stdout, which is the
fastest way to see what a short configuration actually expands to. Nothing is bound
and nothing runs in this mode: it is safe to run against a configuration you are still
editing, and a continuous integration pipeline can gate a configuration change on its
exit code before applying it anywhere.

## Run it

```sh
irontraffic run --config config.yaml
```

`run` is the default, batteries-included mode: the data plane and the control plane in
one process, which is what a standalone deployment or a k3s node wants. Two narrower
modes exist for a horizontally scaled deployment that splits them:

- `irontraffic proxy --config config.yaml` runs the data plane only.
- `irontraffic control --config config.yaml` runs the control plane only.

Every mode accepts the same flags as `validate`: `--workers N`, `--bind ADDR`,
`--upstream ADDR`, and `--mode balanced|shard`, each overriding the matching field in
the configuration document without editing the file. `irontraffic --help` prints the
complete flag list and every exit code.

## Stop it

Send `SIGTERM` (a plain `Ctrl-C` in a foreground shell, or the default signal a
process manager sends). IronTraffic stops accepting new connections immediately and
gives every connection already open up to `shutdown.graceful_timeout_ms` to finish on
its own before closing it, so an in-flight request is not cut off by a routine
restart.

## Where to go next

- `docs/RELEASE.md`: the release build, the four supported platforms, and what
  `scripts/install.sh`'s checksum verification does and does not prove.
- `ARCHITECTURE.md`: how the data plane and control plane fit together, and why this
  is one binary with four modes rather than a family of binaries.
- `docs/THREAT-MODEL.md`: what this proxy defends against, organized by the surface
  that receives untrusted input.
