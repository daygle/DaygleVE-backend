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
    command.rs       #   allowlisted host-tool wrapper with fixed paths
    store.rs         #   per-resource persistent JSON records
```

Handlers authenticate + authorize, then delegate to a service. All host
interaction is isolated in the service layer, which drives the real host tools
(the same approach Proxmox takes) rather than an in-memory mock:

| Subsystem | Backed by |
|-----------|-----------|
| **VMs** (`kvm.rs`) | libvirt via `virsh` (`qemu:///system`); zvol-backed disks; generated domain XML; live VNC console proxied over a websocket |
| **Containers** (`lxc.rs`) | `lxc-*` with a ZFS-backed rootfs (`-B zfs`); cgroup2 CPU/memory limits; veth networking |
| **Storage** (`zfs.rs`) | `zpool`/`zfs` (parsed `-Hp` output) |
| **Networking** (`network.rs`) | `ip`/`bridge` (iproute2 `-j` JSON) |
| **GPUs** (`gpu.rs`) | `/sys/bus/pci` enumeration + `vfio-pci` rebind of the IOMMU group |
| **Metrics** (`metrics.rs`) | `/proc` + `/sys` sampling (CPU/disk/net rates over a short delta window) |
| **Auth** (`auth.rs`) | argon2 password hashing + random bearer tokens with a real TTL |

libvirt/LXC and ZFS are the source of truth for live state; DaygleVE keeps a
small sidecar JSON record per VM/container/bridge (in `state.rs`'s state dir)
for the structured fields the host tools don't round-trip, and always overlays
live power/link state at read time. Where a host tool is absent (e.g. a dev
laptop without `zfs`/`virsh`), list endpoints degrade to empty rather than
erroring.

### Host requirements

The engine expects to run as the dedicated `daygleve` service account on the
appliance. The account has no login shell or sudo access and is granted only the
host groups/devices required by the current direct-tool architecture. The
systemd unit applies filesystem, device, capability, syscall, and network
restrictions; AppArmor is also shipped by the ISO. A root-only preparation unit
creates/migrates the state directory before the backend starts.

The engine expects these host components (the DaygleVE ISO ships all of them):
`libvirt`/`qemu-system-x86_64`, `lxc`, `zfsutils-linux`, `iproute2`, and (for
passthrough) `vfio-pci`. It also needs a writable `DAYGLEVE_STATE_DIR` (default
`/var/lib/daygleve`). Some direct LXC, ZFS, networking, and vfio operations
still require high-risk capabilities; production multi-tenant deployments
should put those operations behind a small root-owned broker.

> **Validation status:** the crate builds clean and its host-independent paths
> (auth, RBAC, `/proc` metrics, the JSON store, graceful degradation) are
> covered by a runtime smoke test. The libvirt/LXC/ZFS/vfio paths issue the
> correct host commands but are exercised on a real node, not in CI.

## API

Served under `/api/v1` (see `DaygleVE-schema/openapi/daygleve.v1.yaml`). A dev
admin is seeded; obtain a token via `POST /api/v1/auth/login` and send it as
`Authorization: Bearer <token>`.

## Running

```sh
cargo run
# DAYGLEVE_LISTEN=0.0.0.0:8080          (default)
# DAYGLEVE_CORS_ORIGINS=http://localhost:5173
# DAYGLEVE_ZPOOL=tank                   (default pool for new datasets/zvols)
# DAYGLEVE_STATE_DIR=/var/lib/daygleve  (persistent records)
# DAYGLEVE_ADMIN_PASSWORD=...           (seeded admin password; change it!)
# DAYGLEVE_TOKEN_TTL_SECS=43200         (bearer token lifetime; default 12h)
# DAYGLEVE_BACKUP_DIR=/var/lib/daygleve/backups
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
