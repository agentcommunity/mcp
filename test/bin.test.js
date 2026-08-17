import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { EventEmitter } from 'node:events';
import test from 'node:test';

import { applyChildExit, buildInvocation, helpText, installSignalForwarding } from '../bin.js';

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

test('package metadata has no install scripts or SDK export', async function () {
  const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));

  assert.equal(manifest.name, '@agentcommunity/mcp');
  assert.equal(manifest.bin['agentcommunity-mcp'], 'bin.js');
  assert.equal(manifest.dependencies['mcp-remote'], '0.1.38');
  assert.equal(manifest.exports, undefined);
  assert.equal(manifest.scripts.preinstall, undefined);
  assert.equal(manifest.scripts.install, undefined);
  assert.equal(manifest.scripts.postinstall, undefined);
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
