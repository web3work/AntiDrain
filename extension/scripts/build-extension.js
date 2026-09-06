import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const EXT_DIR = path.resolve(__dirname, "..");
const DIST_DIR = path.resolve(EXT_DIR, "dist");
const SRC_DIR = path.resolve(EXT_DIR, "src");

console.log("Compiling extension TypeScript...");
const tscPath = path.resolve(EXT_DIR, "../cli/node_modules/typescript/bin/tsc");
execSync(`node "${tscPath}" -p "${path.join(EXT_DIR, "tsconfig.json")}"`, { stdio: "inherit" });

function copyRecursive(src, dest) {
  if (!fs.existsSync(src)) return;
  const stats = fs.statSync(src);
  if (stats.isDirectory()) {
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
    for (const file of fs.readdirSync(src)) {
      copyRecursive(path.join(src, file), path.join(dest, file));
    }
  } else {
    const parent = path.dirname(dest);
    if (!fs.existsSync(parent)) fs.mkdirSync(parent, { recursive: true });
    fs.copyFileSync(src, dest);
  }
}

function cleanModuleExports(filePath) {
  if (fs.existsSync(filePath)) {
    let content = fs.readFileSync(filePath, "utf8");
    content = content.replace(/export\s*\{\s*\}\s*;?/g, "");
    fs.writeFileSync(filePath, content, "utf8");
  }
}

// Clean export {} from non-module files in dist
cleanModuleExports(path.join(DIST_DIR, "content/content.js"));
cleanModuleExports(path.join(DIST_DIR, "inpage/inpage.js"));
cleanModuleExports(path.join(DIST_DIR, "popup/popup.js"));

// 1. Copy popup.html to dist/popup/ and extension/popup/
copyRecursive(path.join(SRC_DIR, "popup/popup.html"), path.join(DIST_DIR, "popup/popup.html"));
copyRecursive(path.join(SRC_DIR, "popup/popup.html"), path.join(EXT_DIR, "popup/popup.html"));

// 2. Copy manifest.json to dist/
copyRecursive(path.join(EXT_DIR, "manifest.json"), path.join(DIST_DIR, "manifest.json"));

// 3. Copy dist compiled JS directly to extension root subfolders
// so that loading EITHER extension/ OR extension/dist/ succeeds in Chrome/Brave
for (const sub of ["background", "content", "inpage", "popup", "vault", "core", "rescue", "signer", "shared"]) {
  copyRecursive(path.join(DIST_DIR, sub), path.join(EXT_DIR, sub));
}

// Clean export {} in extension root subfolders as well
cleanModuleExports(path.join(EXT_DIR, "content/content.js"));
cleanModuleExports(path.join(EXT_DIR, "inpage/inpage.js"));
cleanModuleExports(path.join(EXT_DIR, "popup/popup.js"));

// 4. Ensure icons are in both
copyRecursive(path.join(EXT_DIR, "icons"), path.join(DIST_DIR, "icons"));

console.log("✔ Extension successfully packaged in both extension/ and extension/dist/ ready for Load Unpacked!");
