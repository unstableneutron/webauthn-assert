#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const os = require("os");
const { execSync, spawnSync } = require("child_process");

const {
  getTargetTriple,
  getPackageVersion,
  getBinaryName,
  getAssetName,
  getChecksumFileName,
  getReleaseUrl,
  downloadFile,
  fetchText,
  computeSha256,
  parseChecksums,
  extractTarGz,
  ensureDir,
  makeExecutable,
} = require("./common");

const FORCE_BUILD =
  process.env.npm_config_build_from_source === "true" ||
  process.env.WEBAUTHN_ASSERT_BUILD_FROM_SOURCE === "1";

const SKIP_DOWNLOAD = process.env.WEBAUTHN_ASSERT_SKIP_DOWNLOAD === "1";

async function getBinaryDestPath() {
  const target = getTargetTriple();
  if (!target) {
    return null;
  }

  const binDir = path.join(__dirname, "..", "bin", "native", target);
  ensureDir(binDir);

  return path.join(binDir, getBinaryName());
}

function binaryExists(binaryPath) {
  return fs.existsSync(binaryPath);
}

async function downloadPrebuilt(binaryPath) {
  const target = getTargetTriple();
  const version = getPackageVersion();
  const assetName = getAssetName(version, target);
  const checksumFile = getChecksumFileName(version);

  console.log(`Downloading prebuilt binary for ${target}...`);

  const checksumUrl = getReleaseUrl(version, checksumFile);
  let checksums;

  try {
    const checksumContent = await fetchText(checksumUrl);
    checksums = parseChecksums(checksumContent);
  } catch (err) {
    throw new Error(`Failed to download checksums: ${err.message}`);
  }

  const expectedHash = checksums[assetName];
  if (!expectedHash) {
    throw new Error(`No checksum found for ${assetName}`);
  }

  const assetUrl = getReleaseUrl(version, assetName);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "webauthn-assert-"));
  const tarPath = path.join(tmpDir, assetName);

  try {
    await downloadFile(assetUrl, tarPath);

    const actualHash = await computeSha256(tarPath);
    if (actualHash !== expectedHash) {
      throw new Error(
        `Checksum mismatch!\nExpected: ${expectedHash}\nActual: ${actualHash}`
      );
    }

    console.log("Checksum verified.");

    const extractDir = path.dirname(binaryPath);
    ensureDir(extractDir);

    await extractTarGz(tarPath, extractDir);

    if (!fs.existsSync(binaryPath)) {
      const files = fs.readdirSync(extractDir);
      throw new Error(
        `Binary not found after extraction. Files in dir: ${files.join(", ")}`
      );
    }

    makeExecutable(binaryPath);
    console.log(`Binary installed to ${binaryPath}`);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function buildFromSource(binaryPath) {
  console.log("Building from source...");

  const cargoResult = spawnSync("cargo", ["--version"], {
    stdio: "pipe",
    shell: process.platform === "win32",
  });

  if (cargoResult.status !== 0) {
    throw new Error(
      "Cargo is not installed. Please install Rust: https://rustup.rs/"
    );
  }

  const projectRoot = path.join(__dirname, "..");

  console.log("Running: cargo build --release --locked");

  const buildResult = spawnSync("cargo", ["build", "--release", "--locked"], {
    cwd: projectRoot,
    stdio: "inherit",
    shell: process.platform === "win32",
  });

  if (buildResult.status !== 0) {
    throw new Error(`Cargo build failed with exit code ${buildResult.status}`);
  }

  const sourceBinary = path.join(
    projectRoot,
    "target",
    "release",
    getBinaryName()
  );

  if (!fs.existsSync(sourceBinary)) {
    throw new Error(`Built binary not found at ${sourceBinary}`);
  }

  const destDir = path.dirname(binaryPath);
  ensureDir(destDir);

  fs.copyFileSync(sourceBinary, binaryPath);
  makeExecutable(binaryPath);

  console.log(`Binary installed to ${binaryPath}`);
}

function printPlatformHelp() {
  console.error("\nPlatform-specific dependencies:");

  if (process.platform === "linux") {
    console.error("  Ubuntu/Debian: sudo apt-get install libusb-1.0-0-dev libudev-dev");
    console.error("  Fedora: sudo dnf install libusb1-devel systemd-devel");
    console.error("  Arch: sudo pacman -S libusb systemd");
  } else if (process.platform === "darwin") {
    console.error("  macOS: No additional dependencies required.");
  } else if (process.platform === "win32") {
    console.error("  Windows: Run as Administrator if accessing security keys.");
  }
}

async function main() {
  const binaryPath = await getBinaryDestPath();

  if (!binaryPath) {
    console.error(`Unsupported platform: ${process.platform}-${process.arch}`);
    console.error("Supported: darwin-arm64, darwin-x64, linux-x64, linux-arm64, win32-x64");
    process.exit(1);
  }

  if (binaryExists(binaryPath) && !FORCE_BUILD) {
    console.log(`Binary already exists at ${binaryPath}`);
    return;
  }

  if (FORCE_BUILD) {
    console.log("Force building from source (--build-from-source)");
    try {
      buildFromSource(binaryPath);
      return;
    } catch (err) {
      console.error(`Build from source failed: ${err.message}`);
      printPlatformHelp();
      process.exit(1);
    }
  }

  if (!SKIP_DOWNLOAD) {
    try {
      await downloadPrebuilt(binaryPath);
      return;
    } catch (err) {
      console.log(`Prebuilt download failed: ${err.message}`);
      console.log("Falling back to building from source...");
    }
  }

  try {
    buildFromSource(binaryPath);
  } catch (err) {
    console.error(`\nInstallation failed: ${err.message}`);
    printPlatformHelp();
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(`Installation failed: ${err.message}`);
  process.exit(1);
});
