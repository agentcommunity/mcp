import assert from 'node:assert/strict';
import { execFile, spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { applyChildExit, buildInvocation, helpText, installSignalForwarding } from '../bin.js';

const execFileAsync = promisify(execFile);
const packageRoot = fileURLToPath(new URL('../', import.meta.url));

function quoteForComSpec(argument) {
  return `"${argument.replaceAll('"', '""')}"`;
}

function buildComSpecInvocation(executable, args, environment) {
  const commandLine = [executable, ...args].map(quoteForComSpec).join(' ');

  return {
    command: environment.ComSpec ?? environment.COMSPEC ?? 'cmd.exe',
    args: ['/d', '/s', '/c', `"${commandLine}"`],
  };
}

function buildNpmInvocation(
  args,
  platform = process.platform,
  environment = process.env,
  nodeExecPath = process.execPath,
) {
  if (typeof environment.npm_execpath === 'string' && environment.npm_execpath.length > 0) {
    return { command: nodeExecPath, args: [environment.npm_execpath, ...args] };
  }
  if (platform === 'win32') {
    return buildComSpecInvocation('npm.cmd', args, environment);
  }
  return { command: 'npm', args };
}

function buildInstalledShimInvocation(
  shimPath,
  platform = process.platform,
  environment = process.env,
) {
  return platform === 'win32'
    ? buildComSpecInvocation(shimPath, ['--help'], environment)
    : { command: shimPath, args: ['--help'] };
}

test('builds portable npm invocations for the npm CLI and Windows cmd fallback', function () {
  const npmExecPath = 'C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js';
  const nodeExecPath = 'C:\\Program Files\\nodejs\\node.exe';
  const npmArgs = ['pack', '--pack-destination', 'C:\\Temp Root & Cache\\pack'];

  assert.deepEqual(
    buildNpmInvocation(npmArgs, 'win32', { npm_execpath: npmExecPath }, nodeExecPath),
    {
      command: nodeExecPath,
      args: [npmExecPath, ...npmArgs],
    },
  );
  assert.deepEqual(
    buildNpmInvocation(npmArgs, 'win32', { ComSpec: 'C:\\Windows\\System32\\cmd.exe' }, nodeExecPath),
    {
      command: 'C:\\Windows\\System32\\cmd.exe',
      args: [
        '/d',
        '/s',
        '/c',
        '""npm.cmd" "pack" "--pack-destination" "C:\\Temp Root & Cache\\pack""',
      ],
    },
  );
});

test('builds the installed Windows shim invocation through ComSpec with robust quoting', function () {
  const shimPath = 'C:\\Temp Root & Cache\\node_modules\\.bin\\agentcommunity-mcp.cmd';

  assert.deepEqual(
    buildInstalledShimInvocation(shimPath, 'win32', { COMSPEC: 'C:\\Windows\\cmd.exe' }),
    {
      command: 'C:\\Windows\\cmd.exe',
      args: [
        '/d',
        '/s',
        '/c',
        '""C:\\Temp Root & Cache\\node_modules\\.bin\\agentcommunity-mcp.cmd" "--help""',
      ],
    },
  );
  assert.deepEqual(
    buildInstalledShimInvocation('/tmp/agentcommunity-mcp', 'linux', {}),
    { command: '/tmp/agentcommunity-mcp', args: ['--help'] },
  );
});

async function withPackedInstall(callback) {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'agentcommunity-mcp-'));
  const packDirectory = join(temporaryRoot, 'pack');
  const clientDirectory = join(temporaryRoot, 'client');

  try {
    await mkdir(packDirectory);
    await mkdir(clientDirectory);
    await writeFile(join(clientDirectory, 'package.json'), '{"private":true,"type":"module"}\n');

    const packInvocation = buildNpmInvocation([
      'pack',
      '--json',
      '--pack-destination',
      packDirectory,
    ]);
    const packed = await execFileAsync(packInvocation.command, packInvocation.args, {
      cwd: packageRoot,
    });
    const [{ filename }] = JSON.parse(packed.stdout);
    const installInvocation = buildNpmInvocation([
      'install',
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
      join(packDirectory, filename),
    ]);
    await execFileAsync(installInvocation.command, installInvocation.args, {
      cwd: clientDirectory,
    });

    await callback(clientDirectory);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

test('pins the hosted Agent Community MCP origin before forwarded client arguments', function () {
  const invocation = buildInvocation(['--transport', 'http-only']);

  assert.equal(invocation.command, process.execPath);
  assert.match(invocation.args[0], /node_modules[/\\]mcp-remote[/\\]dist[/\\]proxy\.js$/);
  assert.deepEqual(invocation.args.slice(1), [
    'https://agentcommunity.org/mcp',
    '--transport',
    'http-only',
  ]);
});

test('help describes a connector and never claims to own the server or SDK', function () {
  assert.match(helpText, /Official Agent Community MCP connector/);
  assert.match(helpText, /https:\/\/agentcommunity\.org\/mcp/);
  assert.doesNotMatch(helpText, /SDK|implements four tools|MCP server package/);
});

test('packed package emits help through the installed npm shim', async function () {
  await withPackedInstall(async function (clientDirectory) {
    const shimName = process.platform === 'win32'
      ? 'agentcommunity-mcp.cmd'
      : 'agentcommunity-mcp';
    const shimPath = join(clientDirectory, 'node_modules', '.bin', shimName);
    const helpInvocation = buildInstalledShimInvocation(shimPath);
    const result = await execFileAsync(helpInvocation.command, helpInvocation.args, {
      cwd: clientDirectory,
    });

    assert.match(result.stdout, /Official Agent Community MCP connector/);
    assert.match(result.stdout, /https:\/\/agentcommunity\.org\/mcp/);
    assert.equal(result.stderr, '');
  });
});

test('package metadata has no install scripts or SDK export', async function () {
  const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));

  assert.equal(manifest.name, '@agentcommunity/mcp');
  assert.equal(manifest.bin['agentcommunity-mcp'], 'bin.js');
  assert.equal(manifest.dependencies['mcp-remote'], '0.1.38');
  assert.deepEqual(manifest.exports, {});
  assert.equal(manifest.scripts.preinstall, undefined);
  assert.equal(manifest.scripts.install, undefined);
  assert.equal(manifest.scripts.postinstall, undefined);
});

test('packed package rejects deep imports across the no-SDK boundary', async function () {
  await withPackedInstall(async function (clientDirectory) {
    const result = spawnSync(
      process.execPath,
      ['--input-type=module', '--eval', "await import('@agentcommunity/mcp/bin.js')"],
      { cwd: clientDirectory, encoding: 'utf8' },
    );

    assert.equal(result.status, 1);
    assert.match(result.stderr, /ERR_PACKAGE_PATH_NOT_EXPORTED/);
  });
});

test('forwards host termination signals to the child and removes listeners', function () {
  const host = new EventEmitter();
  const forwarded = [];
  const child = {
    killed: false,
    kill: function (signal) {
      forwarded.push(signal);
      this.killed = true;
    },
  };
  const remove = installSignalForwarding(child, host);

  host.emit('SIGINT');
  host.emit('SIGTERM');
  host.emit('SIGHUP');
  assert.deepEqual(forwarded, ['SIGINT', 'SIGTERM', 'SIGHUP']);

  remove();
  host.emit('SIGTERM');
  assert.deepEqual(forwarded, ['SIGINT', 'SIGTERM', 'SIGHUP']);
});

test('mirrors ordinary exit codes and child termination signals', function () {
  const kills = [];
  const host = { pid: 42, exitCode: undefined, kill: function (pid, signal) { kills.push([pid, signal]); } };

  applyChildExit(7, null, host);
  assert.equal(host.exitCode, 7);
  applyChildExit(null, 'SIGTERM', host);
  assert.deepEqual(kills, [[42, 'SIGTERM']]);
});
