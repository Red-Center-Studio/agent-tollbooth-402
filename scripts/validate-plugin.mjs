import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const errors = [];

function fail(msg) {
  errors.push(msg);
}

function readJson(relPath) {
  const full = path.join(ROOT, relPath);
  if (!existsSync(full)) {
    fail(`Missing required JSON file: ${relPath}`);
    return null;
  }
  try {
    return JSON.parse(readFileSync(full, 'utf8'));
  } catch (err) {
    fail(`Invalid JSON in ${relPath}: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
}

function parseFrontmatter(relPath) {
  const full = path.join(ROOT, relPath);
  if (!existsSync(full)) {
    fail(`Missing markdown file: ${relPath}`);
    return null;
  }
  const text = readFileSync(full, 'utf8');
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n/.exec(text);
  if (!match) {
    fail(`Missing YAML frontmatter in ${relPath}`);
    return null;
  }
  return { raw: match[1], fullText: text, bytes: Buffer.byteLength(text, 'utf8') };
}

// 1. Required deliverable files check
const requiredFiles = [
  'plugin.json',
  '.claude-plugin/plugin.json',
  'mcp_config.json',
  '.mcp.json',
  'skills/scan-routes/SKILL.md',
  'skills/install-tollbooth/SKILL.md',
  'skills/test-agent/SKILL.md',
  'rules/http-402-guardrails.md',
  'packages/edge-middleware/src/index.ts',
  'packages/edge-middleware/test/middleware.test.ts',
  'packages/edge-middleware/package.json',
  'packages/clearinghouse-worker/migrations/0001_init.sql',
  'packages/clearinghouse-worker/src/index.ts',
  'packages/clearinghouse-worker/test/worker.test.ts',
  'packages/clearinghouse-worker/wrangler.jsonc',
  '.gitignore',
  '.env.example',
  'LICENSE',
  'README.md',
  'assets/logo.svg',
];

for (const rel of requiredFiles) {
  const full = path.join(ROOT, rel);
  if (!existsSync(full) || statSync(full).size === 0) {
    fail(`Missing or empty deliverable: ${rel}`);
  }
}

// 2. Validate Antigravity root plugin.json
const agyPlugin = readJson('plugin.json');
if (agyPlugin) {
  const allowedTopKeys = new Set([
    '$schema',
    'name',
    'displayName',
    'version',
    'description',
    'author',
    'homepage',
    'repository',
    'logo',
    'suggestedPrompts',
    'disabled',
  ]);
  for (const key of Object.keys(agyPlugin)) {
    if (!allowedTopKeys.has(key)) {
      fail(`Unsupported top-level key "${key}" in plugin.json`);
    }
  }
  if (typeof agyPlugin.$schema !== 'string' || !agyPlugin.$schema.startsWith('https://')) {
    fail('plugin.json must declare a valid https:// $schema');
  }
  if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(agyPlugin.name ?? '')) {
    fail('plugin.json "name" must be lowercase kebab-case');
  }
  if (typeof agyPlugin.logo !== 'string' || !existsSync(path.join(ROOT, agyPlugin.logo))) {
    fail(`plugin.json "logo" path missing on disk: ${agyPlugin.logo}`);
  }
  if (
    !Array.isArray(agyPlugin.suggestedPrompts) ||
    agyPlugin.suggestedPrompts.length < 1 ||
    agyPlugin.suggestedPrompts.length > 3
  ) {
    fail('plugin.json "suggestedPrompts" must contain 1 to 3 entries');
  }
}

// 3. Validate Claude Code .claude-plugin/plugin.json
const claudePlugin = readJson('.claude-plugin/plugin.json');
if (claudePlugin) {
  if (!/^[a-z][a-z0-9]*(-[a-z0-9]+)*$/.test(claudePlugin.name ?? '')) {
    fail('.claude-plugin/plugin.json "name" must be kebab-case');
  }
  if (!/^\d+\.\d+\.\d+/.test(claudePlugin.version ?? '')) {
    fail('.claude-plugin/plugin.json "version" must be semver');
  }
  if (typeof claudePlugin.description !== 'string' || claudePlugin.description.length < 10) {
    fail('.claude-plugin/plugin.json "description" is required');
  }
}

// 4. Validate MCP configs
const agyMcp = readJson('mcp_config.json');
if (agyMcp) {
  const srv = agyMcp.mcpServers?.['agent-tollbooth-402'];
  if (!srv || srv.url !== 'https://tollbooth.redcenterstudio.com/mcp') {
    fail('mcp_config.json must configure agent-tollbooth-402 -> https://tollbooth.redcenterstudio.com/mcp');
  }
}

const claudeMcp = readJson('.mcp.json');
if (claudeMcp) {
  const srv = claudeMcp.mcpServers?.['agent-tollbooth-402'];
  if (!srv || srv.type !== 'http' || srv.url !== 'https://tollbooth.redcenterstudio.com/mcp') {
    fail('.mcp.json must configure type: "http" and url: "https://tollbooth.redcenterstudio.com/mcp"');
  }
}

// 5. Verify zero runtime dependencies on edge-middleware
const edgePkg = readJson('packages/edge-middleware/package.json');
if (edgePkg && edgePkg.dependencies && Object.keys(edgePkg.dependencies).length > 0) {
  fail('packages/edge-middleware/package.json must have zero runtime dependencies');
}

// 6. Validate Skills & Rule frontmatter
for (const skillName of ['scan-routes', 'install-tollbooth', 'test-agent']) {
  const fm = parseFrontmatter(`skills/${skillName}/SKILL.md`);
  if (fm) {
    if (!new RegExp(`^name:\\s*${skillName}\\s*$`, 'm').test(fm.raw)) {
      fail(`skills/${skillName}/SKILL.md frontmatter name must equal "${skillName}"`);
    }
    if (!/^description:/m.test(fm.raw)) {
      fail(`skills/${skillName}/SKILL.md frontmatter must include description`);
    }
  }
}

const ruleFm = parseFrontmatter('rules/http-402-guardrails.md');
if (ruleFm) {
  if (!/^trigger:\s*model_decision\s*$/m.test(ruleFm.raw)) {
    fail('rules/http-402-guardrails.md must set trigger: model_decision');
  }
  if (!/^description:/m.test(ruleFm.raw)) {
    fail('rules/http-402-guardrails.md must define description');
  }
  if (ruleFm.bytes > 24000) {
    fail(`rules/http-402-guardrails.md exceeds 24,000 byte limit (${ruleFm.bytes})`);
  }
}

// 7. Scan repo files for accidental real secrets
const secretPatterns = [
  /sk_live_[0-9A-Za-z]{16,}/,
  /rk_live_[0-9A-Za-z]{16,}/,
  /whsec_[0-9A-Za-z]{24,}/,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
];

function walkFiles(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (['node_modules', '.git', 'dist', 'coverage'].includes(entry.name)) {
      continue;
    }
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(full);
    } else if (entry.isFile()) {
      const content = readFileSync(full, 'utf8');
      for (const re of secretPatterns) {
        if (re.test(content)) {
          fail(`Potential real secret matched ${re} in ${path.relative(ROOT, full)}`);
        }
      }
    }
  }
}
walkFiles(ROOT);

if (errors.length > 0) {
  console.error('Plugin validation FAILED:');
  for (const e of errors) {
    console.error(` - ${e}`);
  }
  process.exit(1);
}

console.log('Plugin validation PASSED: all manifests, MCP configs, skills, scoped rule, and secret checks passed.');
