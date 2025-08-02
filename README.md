# Minimal mTLS Sidecar Proxy (Rust)

> A zero‑trust, high‑performance sidecar proxy that terminates **mutual TLS (mTLS)** from internal clients and re‑establishes (m)TLS to an upstream service. Written in **Rust** with `tokio`, `hyper`, and `rustls`, and delivered as Infrastructure‑as‑Code via **Terraform**.

![build](https://img.shields.io/badge/build-passing-brightgreen) ![license](https://img.shields.io/badge/license-MIT-blue)

---

## ✨ Features

* **mTLS on both sides** – full client & server certificate validation
* **HTTP/2 via ALPN** – modern transport with multiplexing
* **Asynchronous Rust** – built on `tokio`, scales with cores
* **YAML configuration** – single declarative file for runtime settings
* **Zero‑trust networking** – designed for private + public subnet topology
* **Production‑ready** – Terraform modules (WIP) for AWS EC2, VPC & Secrets Manager

---

## 🗂️ Project layout

```
.
.
├── mtls-proxy/              # Main proxy crate
│   ├── Cargo.toml
│   ├── examples/
│   │   └── proxy.yaml       # YAML config for the proxy
│   └── src/
│       ├── main.rs          # Entry point
│       ├── config.rs        # Clap + Serde YAML config loader
│       ├── proxy.rs         # Accept loop, TLS handling, piping
│       └── tls.rs           # Certificate loading and config
├── upstream-server/         # Minimal upstream server (also Rust)
│   ├── Cargo.toml
│   └── src/main.rs          # Handles incoming mTLS requests
├── mtls-certs/              # Local dev certificates (gitignored)
│   ├── ca.crt, server.crt, client.crt, etc.
├── infra/                   # Terraform IaC (WIP, gitignored)
│   ├── main.tf, outputs.tf, ...
└── README.md
```

---

## 🚀 Quick‑start (local)

### 1. Clone & build

```bash
git clone https://github.com/Hilmernator/mTLS-Sidecar-Proxy.git
cd mTLS-Sidecar-Proxy
cargo build --manifest-path mtls-proxy/Cargo.toml
```

### 2. Generate dev certificates *(optional)*

A helper script is provided under `scripts/dev-certs.sh` or use `mkcert`.

### 3. Start the upstream server

```bash
cargo run --manifest-path upstream-server/Cargo.toml
```

### 4. Start the proxy

```bash
cargo run --manifest-path mtls-proxy/Cargo.toml -- --config mtls-proxy/examples/proxy.yaml
```

### 5. Test with cURL

```bash
curl --http2 -v \
  --cert mtls-certs/client.crt \
  --key  mtls-certs/client.key \
  --cacert mtls-certs/ca.crt \
  https://127.0.0.1:8443
```

Expected output:

```
Hello from upstream
```

---

## ⚙️ Configuration (`proxy.yaml`)

```yaml
listen: "0.0.0.0:8443"          # Where the proxy listens
upstream: "127.0.0.1:9443"      # Upstream host:port (mTLS expected)

tls:
  ca_file: "/etc/mtls/ca.crt"          # CA that issued both client & server certs
  server_cert: "/etc/mtls/proxy.crt"   # Cert presented to local clients
  server_key: "/etc/mtls/proxy.key"
  client_cert: "/etc/mtls/proxy-client.crt" # Cert presented upstream
  client_key: "/etc/mtls/proxy-client.key"
```

* **Absolute paths** recommended in production.
* Same schema is used by the upstream server.

---

## ☁️ AWS Deployment (coming soon)

*Terraform automation is still in progress and **not yet part of the public repository**.*

The current commit focuses on the fully‑functional **local PoC**.  A future PR will introduce:

* Terraform modules for VPC, subnets, EC2 instances and Security Groups.
* Secrets Manager resources for secure certificate distribution.
* `user_data` scripts that pull certs to `/etc/mtls/` and render `proxy.yaml`.

> **Heads‑up:** Both `infra/` and `mtls-certs/` are currently listed in `.gitignore` and will be re‑added (sans private keys) once the IaC code is production‑ready.

---

## 🛣️ Roadmap

* [x] End‑to‑end local mTLS (proxy ↔ upstream)
* [ ] Terraform modules & remote deploy
* [ ] Secrets Manager integration
* [ ] Hot‑reload / cert rotation via `notify`
* [ ] GitHub Actions: build, CodeQL, release binaries

---

## 🤝 Contributing

PRs are welcome!  Please open an issue first to discuss substantial changes.

### Development scripts

```bash
cargo fmt    # formatting
cargo clippy # lints
cargo test   # (coming soon)
```

---

## 📜 License

Licensed under the **MIT License** – see [`LICENSE`](LICENSE) for details.

---

## 🙏 Acknowledgements

* [rustls](https://github.com/rustls/rustls) – modern TLS for Rust
* [tokio](https://github.com/tokio-rs/tokio) – async runtime
* [hyper](https://github.com/hyperium/hyper) & `hyper-util` – HTTP/2 server/client
