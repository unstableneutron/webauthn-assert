#!/usr/bin/env node

const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const TARGETS = {
  "darwin-arm64": "aarch64-apple-darwin",
  "darwin-x64": "x86_64-apple-darwin",
  "linux-x64": "x86_64-unknown-linux-gnu",
  "linux-arm64": "aarch64-unknown-linux-gnu",
  "win32-x64": "x86_64-pc-windows-msvc",
};

function getTargetTriple() {
  const key = `${process.platform}-${process.arch}`;
  return TARGETS[key] || null;
}

function getBinaryPath() {
  const target = getTargetTriple();
  if (!target) {
    return null;
  }

  const ext = process.platform === "win32" ? ".exe" : "";
  const binaryName = `webauthn-assert${ext}`;

  return path.join(__dirname, "native", target, binaryName);
}

function main() {
  const binaryPath = getBinaryPath();

  if (!binaryPath) {
    console.error(
      `Error: Unsupported platform: ${process.platform}-${process.arch}`
    );
    console.error("Please build from source using: cargo build --release");
    process.exit(1);
  }

  if (!fs.existsSync(binaryPath)) {
    console.error(`Error: Binary not found at ${binaryPath}`);
    console.error("Try reinstalling the package: npm install webauthn-assert");
    console.error(
      "Or build from source: npm install webauthn-assert --build-from-source"
    );
    process.exit(1);
  }

  const child = spawn(binaryPath, process.argv.slice(2), {
    stdio: "inherit",
  });

  child.on("error", (err) => {
    console.error(`Failed to start binary: ${err.message}`);
    process.exit(1);
  });

  child.on("close", (code) => {
    process.exit(code ?? 0);
  });
}

main();
