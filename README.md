# hawkeye

Hawkeye is a tracing tool, like [funclatency][1] but with eBPF CO-RE based on [aya][2],
where a single self-contained binary can be deployed on many Linux distributions and kernel versions.

[1]: https://github.com/iovisor/bcc/blob/master/tools/funclatency.py
[2]: https://github.com/aya-rs/aya

## How to use

```bash
Usage: hawkeye [OPTIONS] --hostname <HOSTNAME>

Options:
  -p, --pid <PID>            Process to be traced
  -f, --fn-name <FN_NAME>    Function name [default: fdatasync]
  -w, --webhook <WEBHOOK>    WxWork bot webhook [default: ""]
      --hostname <HOSTNAME>  Hostname
  -h, --help                 Print help
```

## How to build

Install bpf-linker

```bash
cargo install bpf-linker
```

Add musl target

```bash
rustup target add x86_64-unknown-linux-musl
```

Build

```bash
# dev build
cargo xtask build

# release build
cargo xtask build --release

# build eBPF only
cargo xtask build-ebpf

# run
export RUST_LOG=info
cargo xtask run
```
