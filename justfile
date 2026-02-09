set working-directory := "codex-rs"
set positional-arguments

# Display help
help:
    just -l

# `codex`
alias c := codex
codex *args:
    cargo run --bin codex -- "$@"

# `codex exec`
exec *args:
    cargo run --bin codex -- exec "$@"

# Run the CLI version of the file-search crate.
file-search *args:
    cargo run --bin codex-file-search -- "$@"

# Build the CLI and run the app-server test client
app-server-test-client *args:
    cargo build -p codex-cli
    cargo run -p codex-app-server-test-client -- --codex-bin ./target/debug/codex "$@"

# format code
fmt:
    cargo fmt -- --config imports_granularity=Item 2>/dev/null

fix *args:
    cargo clippy --fix --all-features --tests --allow-dirty "$@"

clippy:
    cargo clippy --all-features --tests "$@"

install:
    rustup show active-toolchain
    cargo fetch

# Build and install codex-cli from source.
#
# Pass a destination directory (with or without trailing slash). Optionally pass a
# custom filename:
#   just install-codex /usr/local/bin
#   just install-codex /usr/local/bin codex-cli
#
# Backwards-compatible: you may also pass an explicit destination path ending in
# `codex`/`codex.exe`:
#   just install-codex /usr/local/bin/codex
install-codex dest="$HOME/.cargo/bin" name="":
    cargo build --release -p codex-cli
    set -e; exe_suffix=''; target_dir="$(cargo metadata --format-version=1 --no-deps | jq -r '.target_directory')"; src_bin="${target_dir}/release/codex"; if [ -f "${src_bin}.exe" ]; then exe_suffix='.exe'; src_bin="${src_bin}.exe"; fi; dest_dir="{{dest}}"; name_arg="{{name}}"; if [ -n "$name_arg" ]; then case "$name_arg" in */*|*\\*|'.'|'..'|-*) echo "error: name must be a simple filename" >&2; exit 2 ;; esac; fi; dest_path="$dest_dir"; if [ -n "$name_arg" ]; then dest_path="${dest_dir%/}/$name_arg"; case "$dest_path" in *.[eE][xX][eE]) : ;; *) dest_path="${dest_path}${exe_suffix}" ;; esac; else base="$(basename "$dest_path")"; case "$dest_path" in */) dest_path="${dest_path}codex${exe_suffix}" ;; *) if [ -d "$dest_path" ]; then dest_path="$dest_path/codex${exe_suffix}"; elif [ "$base" != "codex" ] && [ "$base" != "codex.exe" ]; then dest_path="$dest_path/codex${exe_suffix}"; fi ;; esac; fi; mkdir -p -- "$(dirname "$dest_path")"; install -m 0755 -- "$src_bin" "$dest_path"; run_bin="$dest_path"; case "$run_bin" in */*) : ;; *) run_bin="./$run_bin" ;; esac; "$run_bin" --version

# Run `cargo nextest` since it's faster than `cargo test`, though including
# --no-fail-fast is important to ensure all tests are run.
#
# Run `cargo install cargo-nextest` if you don't have it installed.
test:
    cargo nextest run --no-fail-fast

# Build and run Codex from source using Bazel.
# Note we have to use the combination of `[no-cd]` and `--run_under="cd $PWD &&"`
# to ensure that Bazel runs the command in the current working directory.
[no-cd]
bazel-codex *args:
    bazel run //codex-rs/cli:codex --run_under="cd $PWD &&" -- "$@"

bazel-test:
    bazel test //... --keep_going

bazel-remote-test:
    bazel test //... --config=remote --platforms=//:rbe --keep_going

build-for-release:
    bazel build //codex-rs/cli:release_binaries --config=remote

# Run the MCP server
mcp-server-run *args:
    cargo run -p codex-mcp-server -- "$@"

# Regenerate the json schema for config.toml from the current config types.
write-config-schema:
    cargo run -p codex-core --bin codex-write-config-schema

# Regenerate vendored app-server protocol schema artifacts.
write-app-server-schema *args:
    cargo run -p codex-app-server-protocol --bin write_schema_fixtures -- "$@"

# Tail logs from the state SQLite database
log *args:
    if [ "${1:-}" = "--" ]; then shift; fi; cargo run -p codex-state --bin logs_client -- "$@"
