import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const expectedName = '@agentcommunity/mcp';
const expectedFiles = ['LICENSE', 'README.md', 'SECURITY.md', 'bin.js', 'package.json'];
const expectedBin = { 'agentcommunity-mcp': 'bin.js' };
const expectedKeywords = [
  'agentcommunity',
  'agent-community',
  'mcp',
  'model-context-protocol',
  'stdio',
  'streamable-http',
  'ai-agents',
];
const expectedHomepage = 'https://agentcommunity.org/developers';
const expectedRepository = {
  type: 'git',
  url: 'git+https://github.com/agentcommunity/mcp.git',
};
const expectedEngines = { node: '>=20.18.1' };
const expectedDependencies = { 'mcp-remote': '0.1.38' };
const expectedScripts = {
  test: 'node --test',
  'package:audit': 'node scripts/audit-package.mjs',
};
const hostedMcpUrl = 'https://agentcommunity.org/mcp';
const brandedHeading = 'Official Agent Community MCP connector';
const secretPatterns = [
  { label: 'private key', pattern: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/ },
  { label: 'npm token', pattern: /\bnpm_[A-Za-z0-9]{20,}\b/ },
  { label: 'GitHub token', pattern: /\bgh[opusr]_[A-Za-z0-9]{20,}\b/ },
  { label: 'GitHub token', pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/ },
  { label: 'Stripe key', pattern: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b/ },
];

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function decodeBase64UrlJson(segment) {
  try {
    const decoded = Buffer.from(segment, 'base64url');
    if (decoded.toString('base64url') !== segment) return undefined;
    return JSON.parse(decoded.toString('utf8'));
  } catch {
    return undefined;
  }
}

export function containsJwt(content) {
  const candidatePattern = /(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]*)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])/g;

  for (const match of content.matchAll(candidatePattern)) {
    const header = decodeBase64UrlJson(match[1]);
    const payload = decodeBase64UrlJson(match[2]);
    const signature = Buffer.from(match[3], 'base64url');
    const hasCanonicalSignature = signature.toString('base64url') === match[3];

    if (
      isRecord(header)
      && typeof header.alg === 'string'
      && header.alg.length > 0
      && isRecord(payload)
      && hasCanonicalSignature
    ) {
      return true;
    }
  }

  return false;
}

export function installedShimName(platform = process.platform) {
  return platform === 'win32' ? 'agentcommunity-mcp.cmd' : 'agentcommunity-mcp';
}

export async function validateInstalledShimTarget(
  shimPath,
  expectedTargetPath,
  platform = process.platform,
) {
  const expectedTarget = await realpath(expectedTargetPath);

  if (platform === 'win32') {
    assert.equal(
      (await lstat(shimPath)).isFile(),
      true,
      'Clean-install Windows executable shim is not a regular wrapper file',
    );
    const expectedReference = relative(dirname(shimPath), expectedTargetPath).replaceAll('\\', '/');
    const expectedTargetArgument = `%dp0%/${expectedReference}`.toLowerCase();
    const wrapperLines = (await readFile(shimPath, 'utf8'))
      .replaceAll('\\', '/')
      .split(/\r?\n/);
    const invokesExpectedTarget = wrapperLines.some(function (line) {
      const quotedArguments = Array.from(line.matchAll(/"([^"\r\n]*)"/g), function (match) {
        return match[1];
      });
      const programIndex = quotedArguments.findIndex(function (argument) {
        return /^(?:%_prog%|node(?:\.exe)?)$/i.test(argument);
      });

      return programIndex !== -1
        && quotedArguments[programIndex + 1]?.toLowerCase() === expectedTargetArgument
        && line.trimEnd().endsWith('%*');
    });
    assert.equal(
      invokesExpectedTarget,
      true,
      'Clean-install Windows executable shim does not invoke the packed bin.js',
    );
    return expectedTarget;
  }

  assert.equal(
    (await lstat(shimPath)).isSymbolicLink(),
    true,
    'Clean-install executable shim is not a symbolic link',
  );
  const resolvedShim = await realpath(shimPath);
  assert.equal(
    resolvedShim,
    expectedTarget,
    'Clean-install executable shim does not resolve to the packed bin.js',
  );
  return resolvedShim;
}

export function buildShimHelpInvocation(
  shimPath,
  platform = process.platform,
  environment = process.env,
) {
  if (platform === 'win32') {
    return {
      command: environment.ComSpec ?? environment.COMSPEC ?? 'cmd.exe',
      args: ['/d', '/s', '/c', `"${shimPath}" --help`],
    };
  }

  return { command: shimPath, args: ['--help'] };
}

export function parseAuditArguments(argv, cwd = process.cwd()) {
  if (argv.length === 0) return { mode: 'pack' };

  let tarball;
  let packResult;
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag !== '--tarball' && flag !== '--pack-result') {
      throw new Error(`Unknown package audit argument: ${flag ?? '(missing)'}.`);
    }
    if (typeof value !== 'string' || value.length === 0 || value.startsWith('--')) {
      throw new Error(`Package audit argument ${flag} requires a path value.`);
    }
    if (flag === '--tarball') {
      if (tarball !== undefined) throw new Error('Package audit argument --tarball was repeated.');
      tarball = value;
    } else {
      if (packResult !== undefined) {
        throw new Error('Package audit argument --pack-result was repeated.');
      }
      packResult = value;
    }
  }

  if (tarball === undefined || packResult === undefined) {
    throw new Error('Explicit package audit requires both --tarball and --pack-result.');
  }

  const tarballPath = resolve(cwd, tarball);
  const packResultPath = resolve(cwd, packResult);
  if (tarballPath === packResultPath) {
    throw new Error('Tarball and pack-result paths must be distinct.');
  }

  return { mode: 'provided', tarballPath, packResultPath };
}

function command(commandName, args, cwd) {
  const result = spawnSync(commandName, args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });

  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `${commandName} ${args.join(' ')} failed with exit ${result.status}:\n${result.stderr}`,
    );
  }

  return result.stdout;
}

function npmCommand(args, cwd) {
  const npmExecPath = process.env.npm_execpath;

  return npmExecPath === undefined
    ? command(process.platform === 'win32' ? 'npm.cmd' : 'npm', args, cwd)
    : command(process.execPath, [npmExecPath, ...args], cwd);
}

function invalidPackOutput(message) {
  throw new Error(`Invalid npm pack JSON output: ${message}.`);
}

export function normalizePackResult(value, expectedVersion) {
  let candidate;

  if (Array.isArray(value)) {
    if (value.length !== 1) invalidPackOutput('expected exactly one result');
    [candidate] = value;
  } else if (isRecord(value)) {
    const entries = Object.entries(value);
    if (entries.length !== 1 || entries[0][0] !== expectedName) {
      invalidPackOutput('expected exactly one result keyed by the package name');
    }
    candidate = entries[0][1];
  } else {
    invalidPackOutput('top-level value is not an array or package map');
  }

  if (!isRecord(candidate)) invalidPackOutput('result is not an object');
  if (candidate.name !== expectedName || candidate.version !== expectedVersion) {
    invalidPackOutput('result name or version does not match the source manifest');
  }

  const expectedFilename = `agentcommunity-mcp-${expectedVersion}.tgz`;
  if (
    candidate.filename !== expectedFilename
    || basename(candidate.filename) !== candidate.filename
  ) {
    invalidPackOutput('tarball filename is not the expected package filename');
  }
  if (!/^[a-f0-9]{40}$/.test(candidate.shasum)) {
    invalidPackOutput('result shasum is malformed');
  }
  if (!/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(candidate.integrity)) {
    invalidPackOutput('result integrity is malformed');
  }
  if (!Array.isArray(candidate.files)) invalidPackOutput('result files are missing');
  if (candidate.files.some(function (file) {
    return !isRecord(file)
      || typeof file.path !== 'string'
      || file.path.length === 0
      || typeof file.size !== 'number'
      || !Number.isSafeInteger(file.size)
      || file.size < 0;
  })) {
    invalidPackOutput('result files are malformed');
  }

  return candidate;
}

export function assertExactManifest(manifest, expectedVersion, source) {
  assert.equal(manifest.name, expectedName, `${source} package name drift detected`);
  assert.equal(manifest.version, expectedVersion, `${source} package version drift detected`);
  assert.deepEqual(manifest.bin, expectedBin, `${source} binary mapping drift detected`);
  assert.deepEqual(manifest.keywords, expectedKeywords, `${source} keywords drift detected`);
  assert.equal(manifest.homepage, expectedHomepage, `${source} homepage drift detected`);
  assert.deepEqual(
    manifest.repository,
    expectedRepository,
    `${source} repository metadata drift detected`,
  );
  assert.equal(manifest.license, 'MIT', `${source} license drift detected`);
  assert.deepEqual(manifest.engines, expectedEngines, `${source} Node engine drift detected`);
  assert.deepEqual(
    manifest.dependencies,
    expectedDependencies,
    `${source} dependency boundary drift detected`,
  );
  assert.deepEqual(manifest.exports, {}, `${source} exports must be an exact empty map`);
  assert.deepEqual(manifest.scripts, expectedScripts, `${source} scripts map drift detected`);
}

export function assertCompleteManifest(manifest, sourceManifest, source) {
  assertExactManifest(manifest, sourceManifest.version, source);
  assert.deepEqual(manifest, sourceManifest, `${source} complete manifest drift detected`);
}

async function main(argv = process.argv.slice(2)) {
  const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));
  const auditArguments = parseAuditArguments(argv);
  const sourceManifest = JSON.parse(await readFile(join(repositoryRoot, 'package.json'), 'utf8'));
  if (typeof sourceManifest.version !== 'string' || sourceManifest.version.length === 0) {
    throw new Error('Source package version is missing.');
  }
  assertExactManifest(sourceManifest, sourceManifest.version, 'Source');

  let packDirectory;
  let installDirectory;

  try {
    installDirectory = await mkdtemp(join(tmpdir(), 'agentcommunity-mcp-install-'));

    let packOutput;
    let tarballPath;
    if (auditArguments.mode === 'pack') {
      packDirectory = await mkdtemp(join(tmpdir(), 'agentcommunity-mcp-pack-'));
      packOutput = npmCommand(
        ['pack', '--json', '--pack-destination', packDirectory],
        repositoryRoot,
      );
    } else {
      packOutput = await readFile(auditArguments.packResultPath, 'utf8');
    }

    const packResult = normalizePackResult(JSON.parse(packOutput), sourceManifest.version);
    const inventory = packResult.files.map(function (file) { return file.path; }).sort();
    assert.deepEqual(inventory, expectedFiles, 'Unexpected package inventory');

    if (auditArguments.mode === 'pack') {
      tarballPath = join(packDirectory, packResult.filename);
    } else {
      tarballPath = auditArguments.tarballPath;
      assert.equal(
        basename(tarballPath),
        packResult.filename,
        'Provided tarball filename does not match pack-result JSON',
      );
      assert.equal(
        (await lstat(tarballPath)).isFile(),
        true,
        'Provided tarball is not a regular file',
      );
    }

    const tarInventory = command('tar', ['-tzf', tarballPath], repositoryRoot)
      .split(/\r?\n/)
      .filter(function (entry) { return entry.length > 0; })
      .map(function (entry) {
        assert.ok(entry.startsWith('package/'), `Unexpected tarball entry root: ${entry}`);
        return entry.slice('package/'.length);
      })
      .sort();
    assert.deepEqual(tarInventory, expectedFiles, 'Unexpected tarball inventory');

    const packedManifest = JSON.parse(
      command('tar', ['-xOf', tarballPath, 'package/package.json'], repositoryRoot),
    );
    assertCompleteManifest(packedManifest, sourceManifest, 'Packed tarball');

    for (const packedPath of inventory) {
      const content = command(
        'tar',
        ['-xOf', tarballPath, `package/${packedPath}`],
        repositoryRoot,
      );
      for (const { label, pattern } of secretPatterns) {
        if (pattern.test(content)) throw new Error(`Possible ${label} in packed file ${packedPath}.`);
      }
      if (containsJwt(content)) throw new Error(`Possible JWT in packed file ${packedPath}.`);
    }

    const tarball = await readFile(tarballPath);
    const tarballSha256 = createHash('sha256').update(tarball).digest('hex');
    assert.equal(
      createHash('sha1').update(tarball).digest('hex'),
      packResult.shasum,
      'Tarball SHA-1 does not match pack-result JSON',
    );
    assert.equal(
      `sha512-${createHash('sha512').update(tarball).digest('base64')}`,
      packResult.integrity,
      'Tarball integrity does not match pack-result JSON',
    );

    await writeFile(
      join(installDirectory, 'package.json'),
      '{"name":"agentcommunity-mcp-clean-install","private":true,"version":"1.0.0"}\n',
    );
    npmCommand(
      ['install', '--ignore-scripts', '--no-audit', '--no-fund', tarballPath],
      installDirectory,
    );

    const installedPackageRoot = join(
      installDirectory,
      'node_modules',
      '@agentcommunity',
      'mcp',
    );
    const installedManifest = JSON.parse(
      await readFile(join(installedPackageRoot, 'package.json'), 'utf8'),
    );
    assertCompleteManifest(installedManifest, sourceManifest, 'Installed package');

    const installedShim = join(
      installDirectory,
      'node_modules',
      '.bin',
      installedShimName(),
    );
    const installedShimTarget = await validateInstalledShimTarget(
      installedShim,
      join(installedPackageRoot, expectedBin['agentcommunity-mcp']),
    );

    const helpInvocation = buildShimHelpInvocation(installedShim);
    const help = spawnSync(helpInvocation.command, helpInvocation.args, {
      cwd: installDirectory,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
    });
    if (help.error !== undefined) throw help.error;
    assert.equal(help.status, 0, `Clean-install help smoke exited ${help.status}:\n${help.stderr}`);
    assert.ok(help.stdout.includes(brandedHeading), 'Connector heading is missing from help');
    assert.ok(help.stdout.includes(hostedMcpUrl), 'Hosted MCP URL is missing from help');

    process.stdout.write(`${JSON.stringify({
      artifact_source: auditArguments.mode === 'pack' ? 'packed' : 'provided',
      filename: packResult.filename,
      sha256: tarballSha256,
      files: inventory,
      installed_shim_target: installedShimTarget,
      clean_install_help: 'passed',
    }, null, 2)}\n`);
  } finally {
    await Promise.all([
      packDirectory === undefined
        ? Promise.resolve()
        : rm(packDirectory, { recursive: true, force: true }),
      installDirectory === undefined
        ? Promise.resolve()
        : rm(installDirectory, { recursive: true, force: true }),
    ]);
  }
}

function isMainModule() {
  return typeof process.argv[1] === 'string'
    && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
}

if (isMainModule()) await main();
