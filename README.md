# sealhook

`sealhook` is a small, fast Git-hook utility for repositories that keep
plaintext secret files local-only while tracking encrypted `*.age` artifacts in
Git.

Typical workflow:

- keep `.env` or other plaintext secret files in the working tree only;
- commit `.env.age` or another encrypted artifact;
- run `sealhook encrypt --stage` from a pre-commit hook;
- run `sealhook decrypt` after checkout/merge/rewrite to refresh local
  plaintext files when encrypted artifacts changed;
- run `sealhook check-staged` to block accidental plaintext staging.

## Why `age` CLI instead of embedding an age library?

`sealhook` intentionally shells out to the system-installed `age` command-line
interface instead of linking an age implementation into the binary.

That tradeoff is deliberate:

1. **Long-term maintenance:** `age` itself is the stable interface people install,
   audit, package, and upgrade. Depending on the local CLI means `sealhook` can
   stay a thin orchestration layer rather than becoming a cryptography runtime.
2. **Upgrade flexibility:** security fixes and platform packaging improvements in
   `age` are picked up by upgrading the system `age` package, without rebuilding
   `sealhook`.
3. **Operational transparency:** users can reproduce every crypto operation with
   plain `age` commands. `sealhook` only decides *when* and *which files* to
   encrypt/decrypt.
4. **Smaller trust surface:** Rust handles manifest parsing, file sync logic,
   safe overwrite behavior, and hook integration; `age` handles cryptography.
5. **Better longevity:** a hook utility that depends on a widely packaged CLI is
   less likely to be stranded by a stale embedded crypto dependency.

The result should still feel fast and robust: `sealhook` does minimal process
spawning, writes through temporary files, preserves mtimes after sync, avoids
unsafe plaintext overwrite by default, and exits with predictable status codes
for hook usage.

## Requirements

- Rust toolchain for building `sealhook`.
- `age` and `age-keygen` installed on machines that run encryption/decryption.
- Git, when using `--stage` or `check-staged`.
- Optional: `prek` for hook management.

On macOS with Homebrew:

```bash
brew install age rust prek
```

## Install

```bash
cargo install sealhook
```

`sealhook` still requires the system `age` CLI at runtime, so install `age`
through your platform package manager as well.

## Verify

```bash
cargo test
cargo build --release
cargo clippy --all-targets -- -D warnings
./target/release/sealhook --help
```

Install the release binary somewhere on PATH when using `sealhook` from another
repository, for example `/usr/local/bin`, `/opt/homebrew/bin`, or a project-local
tool directory managed outside this source tree.

## Minimal config

Create `.sealhook.toml` in the repository that owns the secret files:

```toml
[sealhook]
engine = "age"

[[secrets]]
path = ".env"
```

Defaults:

- engine: `age`
- recipients file: `.age-recipients`
- identity files: `~/.config/age/keys.txt`, `~/.config/age/se.key`
- armor: `false`
- encrypted path: `<path>.age`
- plaintext mode after decrypt: `0600`

Expanded example:

```toml
[sealhook]
engine = "age"

[age]
recipients_file = ".age-recipients"
identity_files = ["~/.config/age/keys.txt", "~/.config/age/se.key"]
armor = false

[[secrets]]
path = ".env"
encrypted = ".env.age"
mode = "0600"

[[secrets]]
path = "config/local-secrets.json"
# encrypted defaults to "config/local-secrets.json.age"
```

`.age-recipients` should contain one age recipient per line:

```text
age1...
```

Keep plaintext secret files ignored, but allow encrypted artifacts to be tracked:

```gitignore
.env
!.env.age
```

Recommended `.gitattributes`:

```gitattributes
*.age binary
*.age -diff
```

## Commands

```bash
sealhook [--config .sealhook.toml] encrypt [--stage] [--force]
sealhook [--config .sealhook.toml] decrypt [--force]
sealhook [--config .sealhook.toml] status
sealhook [--config .sealhook.toml] check-staged
```

### `encrypt`

Encrypts plaintext files that are newer than their encrypted artifact.

```bash
sealhook encrypt
sealhook encrypt --stage
```

`--stage` runs `git add` on changed encrypted artifacts, which is useful in a
pre-commit hook.

### `decrypt`

Decrypts encrypted artifacts when they are newer than plaintext files or when the
plaintext file is missing.

```bash
sealhook decrypt
```

By default, `decrypt` refuses to overwrite a plaintext file that is newer than
its encrypted artifact. Use `--force` only when you intentionally want to replace
local plaintext.

### `status`

Reports whether each plaintext/encrypted pair is in sync.

```bash
sealhook status
```

### `check-staged`

Fails when a configured plaintext secret path is staged in Git.

```bash
sealhook check-staged
```

Use this after `encrypt --stage` in pre-commit hooks to prevent accidental
plaintext commits.

## `prek` integration

`prek` can manage multiple Git hook types using a repo-local `prek.toml`.

Example:

```toml
default_install_hook_types = [
  "pre-commit",
  "post-checkout",
  "post-merge",
  "post-rewrite",
]

[[repos]]
repo = "local"

[[repos.hooks]]
id = "sealhook-encrypt-secrets"
name = "Encrypt changed secrets"
entry = "sealhook encrypt --stage"
language = "system"
pass_filenames = false
always_run = true
stages = ["pre-commit"]
priority = 10

[[repos.hooks]]
id = "block-plaintext-secrets"
name = "Block staged plaintext secrets"
entry = "sealhook check-staged"
language = "system"
pass_filenames = false
always_run = true
stages = ["pre-commit"]
priority = 20

[[repos.hooks]]
id = "sealhook-decrypt-secrets"
name = "Decrypt changed secrets"
entry = "sealhook decrypt"
language = "system"
pass_filenames = false
always_run = true
stages = ["post-checkout", "post-merge", "post-rewrite"]
priority = 10
```

Install hooks:

```bash
prek install --overwrite --prepare-hooks
```

Important: Git does not activate hooks just because a hook config exists in the
repository. Each clone still needs a bootstrap/install step such as the `prek
install` command above.

## Design notes

`sealhook` is intentionally not a secret format. It is a synchronization and hook
orchestration tool:

- the encrypted format is whatever `age` writes;
- recipients and identities are standard age concepts;
- plaintext files remain local-only and should be ignored by Git;
- encrypted artifacts are normal Git-tracked files;
- hook behavior is explicit and reproducible from command-line invocations.

This keeps the project focused: Rust for fast/robust repo automation, and `age`
for cryptography.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
