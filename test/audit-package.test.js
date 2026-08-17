import assert from 'node:assert/strict';
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const auditModulePromise = import('../scripts/audit-package.mjs');

test('validates and invokes the regular npm cmd shim on Windows', async function () {
  const audit = await auditModulePromise;
  assert.equal(typeof audit.installedShimName, 'function');
  assert.equal(typeof audit.validateInstalledShimTarget, 'function');
  assert.equal(typeof audit.buildShimHelpInvocation, 'function');

  const temporaryRoot = await mkdtemp(join(tmpdir(), 'agentcommunity-mcp-windows-shim-'));
  const shimDirectory = join(temporaryRoot, 'node_modules', '.bin');
  const packageDirectory = join(temporaryRoot, 'node_modules', '@agentcommunity', 'mcp');
  const shimPath = join(shimDirectory, 'agentcommunity-mcp.cmd');
  const targetPath = join(packageDirectory, 'bin.js');

  try {
    await mkdir(shimDirectory, { recursive: true });
    await mkdir(packageDirectory, { recursive: true });
    await writeFile(targetPath, '#!/usr/bin/env node\n');
    await writeFile(
      shimPath,
      '@ECHO off\r\n"%_prog%" "%dp0%\\..\\@agentcommunity\\mcp\\bin.js" %*\r\n',
    );

    assert.equal(audit.installedShimName('win32'), 'agentcommunity-mcp.cmd');
    assert.equal(audit.installedShimName('linux'), 'agentcommunity-mcp');
    assert.equal(
      await audit.validateInstalledShimTarget(shimPath, targetPath, 'win32'),
      await realpath(targetPath),
    );
    assert.deepEqual(
      audit.buildShimHelpInvocation(shimPath, 'win32', { ComSpec: 'C:\\Windows\\cmd.exe' }),
      {
        command: 'C:\\Windows\\cmd.exe',
        args: ['/d', '/s', '/c', `"${shimPath}" --help`],
      },
    );
    assert.deepEqual(
      audit.buildShimHelpInvocation('/tmp/agentcommunity-mcp', 'linux', {}),
      { command: '/tmp/agentcommunity-mcp', args: ['--help'] },
    );

    await writeFile(
      shimPath,
      '@ECHO off\r\n"%_prog%" "%dp0%\\..\\@agentcommunity\\mcp\\bin.js.evil" %*\r\n',
    );
    await assert.rejects(
      audit.validateInstalledShimTarget(shimPath, targetPath, 'win32'),
      /does not invoke the packed bin\.js/,
    );

    await writeFile(
      shimPath,
      '@ECHO off\r\n"%_prog%" "%dp0%\\..\\other-package\\bin.js" %*\r\n',
    );
    await assert.rejects(
      audit.validateInstalledShimTarget(shimPath, targetPath, 'win32'),
      /does not invoke the packed bin\.js/,
    );
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('detects a JWT with the minimal valid header without matching invalid JSON', async function () {
  const audit = await auditModulePromise;
  assert.equal(typeof audit.containsJwt, 'function');

  const minimalHeaderToken = [
    'eyJhbGciOiJIUzI1NiJ9',
    'eyJzdWIiOiIxIn0',
    'c2lnbmF0dXJl',
  ].join('.');
  assert.equal(audit.containsJwt(minimalHeaderToken), true);
  assert.equal(
    audit.containsJwt('eyJhbGciOiJIUzI1NiJ9.bm90LWpzb24.c2lnbmF0dXJl'),
    false,
  );
});
