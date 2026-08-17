#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { readFileSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const remoteManifestPath = require.resolve('mcp-remote/package.json');
const remoteManifest = JSON.parse(readFileSync(remoteManifestPath, 'utf8'));
const remoteBin = remoteManifest.bin?.['mcp-remote'];

if (typeof remoteBin !== 'string') {
  throw new Error('Installed mcp-remote package does not expose its expected executable.');
}

const remoteExecutable = join(dirname(remoteManifestPath), remoteBin);
const remoteUrl = 'https://agentcommunity.org/mcp';

export const helpText = `Official Agent Community MCP connector

Usage: agentcommunity-mcp [mcp-remote options]

Bridges a local stdio MCP client to ${remoteUrl}.
The hosted endpoint is anonymous; this connector stores no credentials.
`;

export function buildInvocation(argv = process.argv.slice(2)) {
  return {
    command: process.execPath,
    args: [remoteExecutable, remoteUrl, ...argv],
  };
}

const terminationSignals = ['SIGINT', 'SIGTERM', 'SIGHUP'];

export function installSignalForwarding(child, hostProcess = process) {
  const handlers = new Map();
  for (const signal of terminationSignals) {
    const handler = function () {
      child.kill(signal);
    };
    handlers.set(signal, handler);
    hostProcess.on(signal, handler);
  }
  return function removeSignalForwarding() {
    for (const [signal, handler] of handlers) hostProcess.off(signal, handler);
  };
}

export function applyChildExit(code, signal, hostProcess = process) {
  if (signal !== null) {
    hostProcess.kill(hostProcess.pid, signal);
    return;
  }
  hostProcess.exitCode = code ?? 1;
}

export function main(argv = process.argv.slice(2)) {
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(helpText);
    return;
  }

  const invocation = buildInvocation(argv);
  const child = spawn(invocation.command, invocation.args, {
    stdio: 'inherit',
    env: process.env,
  });
  const removeSignalForwarding = installSignalForwarding(child);

  child.once('error', function (error) {
    removeSignalForwarding();
    process.stderr.write(`agentcommunity-mcp: ${error.message}\n`);
    process.exitCode = 1;
  });
  child.once('exit', function (code, signal) {
    removeSignalForwarding();
    applyChildExit(code, signal);
  });
}

function isMainModule() {
  if (typeof process.argv[1] !== 'string') return false;

  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
}

if (isMainModule()) main();
