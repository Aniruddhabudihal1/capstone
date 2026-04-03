#!/usr/bin/env node
// postinstall.js — benign package: simulates normal post-install behavior.
'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const https = require('https');

// 1. Read package.json itself (normal file I/O)
const pkgPath = path.join(__dirname, 'package.json');
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
console.log('[benign] Read package.json — name:', pkg.name, 'version:', pkg.version);

// 2. Create a temp file in /tmp, write, read back, delete
const tmpFile = path.join(os.tmpdir(), `benign-test-${process.pid}.tmp`);
fs.writeFileSync(tmpFile, 'benign temp data\n', 'utf8');
const tmpData = fs.readFileSync(tmpFile, 'utf8');
fs.unlinkSync(tmpFile);
console.log('[benign] Temp file created, read (' + tmpData.trim() + '), and deleted:', tmpFile);

// 3. Make one HTTPS GET to httpbin.org/get
https.get('https://httpbin.org/get', (res) => {
  let body = '';
  res.on('data', (chunk) => { body += chunk; });
  res.on('end', () => {
    try {
      const json = JSON.parse(body);
      console.log('[benign] HTTPS GET https://httpbin.org/get — status:', res.statusCode,
                  'origin:', json.origin);
    } catch (e) {
      console.log('[benign] HTTPS GET https://httpbin.org/get — status:', res.statusCode);
    }
    console.log('[benign] postinstall complete.');
  });
}).on('error', (err) => {
  console.log('[benign] HTTPS GET failed (non-fatal):', err.message);
  console.log('[benign] postinstall complete.');
});
