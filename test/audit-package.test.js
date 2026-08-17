import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const auditModulePromise = import('../scripts/audit-package.mjs');
const execFileAsync = promisify(execFile);
const packageRoot = fileURLToPath(new URL('../', import.meta.url));
const auditScript = fileURLToPath(new URL('../scripts/audit-package.mjs', import.meta.url));

async function executeNpm(args, cwd) {
  if (process.env.npm_execpath !== undefined) {
    return execFileAsync(process.execPath, [process.env.npm_execpath, ...args], { cwd });
  }
  if (process.platform === 'win32') {
    const commandLine = ['npm', ...args]
      .map(function (argument) { return `"${argument.replaceAll('"', '""')}"`; })
      .join(' ');
    return execFileAsync(
      process.env.ComSpec ?? process.env.COMSPEC ?? 'cmd.exe',
      ['/d', '/s', '/c', commandLine],
      { cwd },
    );
  }
  return execFileAsync('npm', args, { cwd });
}

function firstPackResult(value) {
  return Array.isArray(value) ? value[0] : Object.values(value)[0];
}

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

test('audits a caller-owned exact tarball without repacking or deleting it', async function () {
  const artifactDirectory = await mkdtemp(join(tmpdir(), 'agentcommunity-mcp-exact-artifact-'));
  const packResultPath = join(artifactDirectory, 'pack-result.json');

  try {
    const packed = await executeNpm(
      ['pack', '--json', '--pack-destination', artifactDirectory],
      packageRoot,
    );
    await writeFile(packResultPath, packed.stdout);
    const packResult = firstPackResult(JSON.parse(packed.stdout));
    const tarballPath = join(artifactDirectory, packResult.filename);
    const beforeHash = createHash('sha256').update(await readFile(tarballPath)).digest('hex');

    const audited = await execFileAsync(
      process.execPath,
      [auditScript, '--tarball', tarballPath, '--pack-result', packResultPath],
      { cwd: packageRoot, maxBuffer: 16 * 1024 * 1024 },
    );
    const auditResult = JSON.parse(audited.stdout);

    assert.equal(auditResult.artifact_source, 'provided');
    assert.equal(auditResult.filename, packResult.filename);
    assert.equal(auditResult.sha256, beforeHash);
    await access(tarballPath);
    await access(packResultPath);
    assert.equal(
      createHash('sha256').update(await readFile(tarballPath)).digest('hex'),
      beforeHash,
    );

    await writeFile(
      tarballPath,
      Buffer.concat([await readFile(tarballPath), Buffer.from('tampered')]),
    );
    await assert.rejects(
      execFileAsync(
        process.execPath,
        [auditScript, '--tarball', tarballPath, '--pack-result', packResultPath],
        { cwd: packageRoot, maxBuffer: 16 * 1024 * 1024 },
      ),
      /Tarball SHA-1 does not match pack-result JSON/,
    );
    await access(tarballPath);
    await access(packResultPath);
  } finally {
    await rm(artifactDirectory, { recursive: true, force: true });
  }
});

test('requires a paired explicit artifact CLI contract', async function () {
  const audit = await auditModulePromise;
  assert.equal(typeof audit.parseAuditArguments, 'function');
  const fixtureWorkspace = resolve(packageRoot, 'fixture-workspace');

  assert.deepEqual(audit.parseAuditArguments([], fixtureWorkspace), { mode: 'pack' });
  assert.deepEqual(
    audit.parseAuditArguments(
      ['--tarball', 'release.tgz', '--pack-result', 'pack-result.json'],
      fixtureWorkspace,
    ),
    {
      mode: 'provided',
      tarballPath: join(fixtureWorkspace, 'release.tgz'),
      packResultPath: join(fixtureWorkspace, 'pack-result.json'),
    },
  );
  assert.throws(
    function () { audit.parseAuditArguments(['--tarball', 'release.tgz'], fixtureWorkspace); },
    /requires both --tarball and --pack-result/,
  );
  assert.throws(
    function () { audit.parseAuditArguments(['--unknown', 'value'], fixtureWorkspace); },
    /Unknown package audit argument/,
  );
});

test('requires complete manifest equality and the exact scripts map', async function () {
  const audit = await auditModulePromise;
  assert.equal(typeof audit.assertExactManifest, 'function');
  assert.equal(typeof audit.assertCompleteManifest, 'function');

  const sourceManifest = JSON.parse(
    await readFile(new URL('../package.json', import.meta.url), 'utf8'),
  );
  const lifecycleDrift = structuredClone(sourceManifest);
  lifecycleDrift.scripts.prepare = 'node unexpected-prepare.js';
  assert.throws(
    function () {
      audit.assertExactManifest(lifecycleDrift, lifecycleDrift.version, 'Source');
    },
    /scripts map drift detected/,
  );

  const metadataDrift = structuredClone(sourceManifest);
  metadataDrift.description = `${metadataDrift.description} changed`;
  assert.throws(
    function () {
      audit.assertCompleteManifest(metadataDrift, sourceManifest, 'Packed tarball');
    },
    /complete manifest drift detected/,
  );
});

test('release workflow packs once then audits and publishes the same tarball path', async function () {
  const workflow = await readFile(
    new URL('../.github/workflows/release.yml', import.meta.url),
    'utf8',
  );

  assert.equal(workflow.match(/\bnpm pack\b/g)?.length, 1);
  assert.match(
    workflow,
    /npm run package:audit -- --tarball "\$tarball" --pack-result "\$pack_result"/,
  );
  assert.match(workflow, /npm publish "\$tarball" --access public --provenance/);
  assert.ok(workflow.indexOf('npm pack ') < workflow.indexOf('npm run package:audit --'));
  assert.ok(workflow.indexOf('npm run package:audit --') < workflow.indexOf('npm publish "$tarball"'));
});
