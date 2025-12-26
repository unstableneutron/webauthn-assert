#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const packageJsonPath = path.join(__dirname, "..", "package.json");
const cargoTomlPath = path.join(__dirname, "..", "Cargo.toml");

const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
const cargoToml = fs.readFileSync(cargoTomlPath, "utf8");

const cargoVersionMatch = cargoToml.match(/^version\s*=\s*"([^"]+)"/m);
if (!cargoVersionMatch) {
  console.error("Could not find version in Cargo.toml");
  process.exit(1);
}

const cargoVersion = cargoVersionMatch[1];
const npmVersion = packageJson.version;

if (cargoVersion !== npmVersion) {
  console.error(`Version mismatch!`);
  console.error(`  Cargo.toml: ${cargoVersion}`);
  console.error(`  package.json: ${npmVersion}`);
  console.error(`\nPlease ensure both versions match.`);
  process.exit(1);
}

console.log(`Versions match: ${cargoVersion}`);
