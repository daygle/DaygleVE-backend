<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/daygleve-logo-dark.svg">
    <img alt="DaygleVE" src="assets/brand/daygleve-logo.svg" width="320" height="77">
  </picture>
</p>

<h1 align="center">DaygleVE-backend</h1>

<p align="center">
The <strong>hypervisor engine</strong> for <a href="https://github.com/daygle">DaygleVE</a> —
a modern, single-node virtualization platform (a faster, safer, cleaner
alternative to Proxmox). Written in Rust with
<a href="https://github.com/tokio-rs/axum">Axum</a> + <a href="https://tokio.rs">Tokio</a>.
</p>

## Responsibilities

- KVM/QEMU virtual-machine lifecycle
- LXC container lifecycle
- ZFS dataset / snapshot / clone / send
- Linux bridge + VLAN networking
- GPU passthrough (vfio-pci)
- Metrics (CPU, RAM, disk, network, guest state) incl. real-time SSE
- Authentication + RBAC
- A clean, versioned REST API

Clustering and Ceph are explicitly **out of scope**.

## Repo boundary

- Imports **all** API types from
  [`DaygleVE-schema`](https://github.com/daygle/DaygleVE-schema); never
  redefines wire shapes locally.
- Contains **no** frontend code.

## Architecture

```
src/
  main.rs            # entrypoint: config → state → router → serve
  config.rs          # env-sourced configuration
  error.rs           # AppError → schema ApiError + HTTP status mapping
  state.rs           # AppState (config + services)
  auth/              # AuthUser extractor + RBAC enforcement
  api/               # thin HTTP handlers, one module per subsystem
    mod.rs           #   router mounted under /api/v1
    health.rs auth.rs vms.rs containers.rs
    storage.rs network.rs gpus.rs metrics.rs
  services/          # subsystem logic (host interaction lives here)
    kvm.rs lxc.rs zfs.rs network.rs gpu.rs metrics.rs auth.rs
```

Handlers authenticate + authorize, then delegate to a service. All host
interaction (libvirt/QEMU, lxc, zfs, ip/bridge, vfio, /proc) is isolated in the
service layer. In this architecture-setup scaffold the services are backed by
in-memory state with `TODO(...)` markers where real host calls attach, so the
API surface and repo boundaries are exercisable end-to-end.

## API

Served under `/api/v1` (see `DaygleVE-schema/openapi/daygleve.v1.yaml`). A dev
admin is seeded; obtain a token via `POST /api/v1/auth/login` and send it as
`Authorization: Bearer <token>`.

## Running

```sh
cargo run
# DAYGLEVE_LISTEN=0.0.0.0:8080  (default)
# DAYGLEVE_CORS_ORIGINS=http://localhost:5173
# DAYGLEVE_ZPOOL=tank
curl localhost:8080/api/v1/health
```

## Development

```sh
cargo fmt --check
cargo clippy --all-targets
cargo test
cargo build
```

## License

Apache-2.0.
