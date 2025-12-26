const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const TARGETS = {
  "darwin-arm64": "aarch64-apple-darwin",
  "darwin-x64": "x86_64-apple-darwin",
  "linux-x64": "x86_64-unknown-linux-gnu",
  "linux-arm64": "aarch64-unknown-linux-gnu",
  "win32-x64": "x86_64-pc-windows-msvc",
};

const REPO_OWNER = "unstableneutron";
const REPO_NAME = "webauthn-assert";

function getTargetTriple() {
  const key = `${process.platform}-${process.arch}`;
  return TARGETS[key] || null;
}

function getPackageVersion() {
  const packageJson = require("../package.json");
  return packageJson.version;
}

function getBinaryName() {
  const ext = process.platform === "win32" ? ".exe" : "";
  return `webauthn-assert${ext}`;
}

function getAssetName(version, target) {
  return `webauthn-assert-v${version}-${target}.tar.gz`;
}

function getChecksumFileName(version) {
  return `checksums-v${version}.txt`;
}

function getReleaseUrl(version, assetName) {
  return `https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/v${version}/${assetName}`;
}

function downloadFile(url, destPath, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    if (maxRedirects <= 0) {
      return reject(new Error("Too many redirects"));
    }

    const protocol = url.startsWith("https") ? https : http;

    protocol
      .get(url, (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400) {
          const redirectUrl = response.headers.location;
          if (!redirectUrl) {
            return reject(new Error("Redirect without location header"));
          }
          return downloadFile(redirectUrl, destPath, maxRedirects - 1)
            .then(resolve)
            .catch(reject);
        }

        if (response.statusCode !== 200) {
          return reject(
            new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`)
          );
        }

        const file = fs.createWriteStream(destPath);
        response.pipe(file);

        file.on("finish", () => {
          file.close();
          resolve();
        });

        file.on("error", (err) => {
          fs.unlink(destPath, () => {});
          reject(err);
        });
      })
      .on("error", (err) => {
        reject(err);
      });
  });
}

function fetchText(url, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    if (maxRedirects <= 0) {
      return reject(new Error("Too many redirects"));
    }

    const protocol = url.startsWith("https") ? https : http;

    protocol
      .get(url, (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400) {
          const redirectUrl = response.headers.location;
          if (!redirectUrl) {
            return reject(new Error("Redirect without location header"));
          }
          return fetchText(redirectUrl, maxRedirects - 1)
            .then(resolve)
            .catch(reject);
        }

        if (response.statusCode !== 200) {
          return reject(
            new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`)
          );
        }

        let data = "";
        response.on("data", (chunk) => (data += chunk));
        response.on("end", () => resolve(data));
      })
      .on("error", reject);
  });
}

function computeSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);

    stream.on("data", (data) => hash.update(data));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", reject);
  });
}

function parseChecksums(content) {
  const checksums = {};
  const lines = content.trim().split("\n");

  for (const line of lines) {
    const match = line.match(/^([a-f0-9]{64})\s+(.+)$/);
    if (match) {
      checksums[match[2]] = match[1];
    }
  }

  return checksums;
}

function extractTarGz(tarPath, destDir) {
  const { spawnSync } = require("child_process");

  const result = spawnSync("tar", ["xzf", tarPath, "-C", destDir], {
    stdio: "pipe",
    shell: process.platform === "win32",
  });

  if (result.status !== 0) {
    const stderr = result.stderr?.toString() || "";
    throw new Error(`tar extraction failed: ${stderr}`);
  }
}

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function makeExecutable(filePath) {
  if (process.platform !== "win32") {
    fs.chmodSync(filePath, 0o755);
  }
}

module.exports = {
  TARGETS,
  REPO_OWNER,
  REPO_NAME,
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
};
