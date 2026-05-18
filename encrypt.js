#!/usr/bin/env node

const { execSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Parse .env
const envPath = path.join(process.cwd(), '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const match = line.match(/^([^=]+)=(.*)$/);
    if (match) process.env[match[1].trim()] = match[2].trim();
  });
}

const MASTER_SECRET = process.env.MASTER_SECRET;
if (!MASTER_SECRET) {
  console.error('Error: MASTER_SECRET not found in .env');
  process.exit(1);
}

// Unique password per file — same master + same path = same password every time
function derivePassword(relPath) {
  return crypto.createHmac('sha256', MASTER_SECRET).update(relPath).digest('hex');
}

// Consistent salt per file — prevents "Remember me" breaking on re-encryption
function deriveSalt(relPath) {
  return crypto.createHmac('sha256', MASTER_SECRET).update('salt:' + relPath).digest('hex').slice(0, 32);
}

function walkHtml(dir, base) {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) results.push(...walkHtml(full, base));
    else if (entry.name.endsWith('.html')) results.push(path.relative(base, full));
  }
  return results;
}

const SRC = 'public-encrypted';
const OUT = 'docs';
const files = walkHtml(SRC, SRC);

if (!files.length) {
  console.log('Nothing to encrypt — public-encrypted/ is empty.');
  process.exit(0);
}

for (const rel of files) {
  const src = path.join(SRC, rel);
  const outDir = path.join(OUT, path.dirname(rel));
  const password = derivePassword(rel);
  const salt = deriveSalt(rel);

  fs.mkdirSync(outDir, { recursive: true });

  execSync(
    `./node_modules/.bin/staticrypt "${src}" -p "${password}" -d "${outDir}" -s "${salt}" --remember 30 --short --config false`,
    { stdio: 'inherit', cwd: process.cwd() }
  );

  console.log(`Encrypted: ${rel}`);
}

console.log(`\nDone. ${files.length} file(s) encrypted to ${OUT}/`);
