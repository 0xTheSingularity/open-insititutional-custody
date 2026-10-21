// Real WASM + Chromium WebAuthn + native Executor/3-of-4 certificate bridge.
// Test keys, simulated UV, fixed clock, and deterministic committee are NOT
// hardware attestation or a running Simplex network.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createPrivateKey } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const [fixtureDir, buildDir, artifactDir, chain = 'evm'] = process.argv.slice(2).map((s, i) => i < 3 ? resolve(s) : s);
const root = process.cwd();
const fixtureBin = resolve(process.env.FIXTURE_BIN || 'target/debug/examples/browser-fixture');
const readJson = name => JSON.parse(readFileSync(join(fixtureDir, name), 'utf8'));
const credential = readJson('virtual-credential.json');
const initial = readJson('initial.json'), pkg = readJson('package.json');
let entries = [initial], publishApproval = false, submitted;
mkdirSync(artifactDir, { recursive: true });
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost:4317');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Frame-Options', 'DENY');
    if (req.method === 'POST' && url.pathname === '/approve') {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      submitted = Buffer.concat(chunks).toString('utf8');
      writeFileSync(join(fixtureDir, 'command.json'), submitted);
      const result = spawnSync(fixtureBin, ['order', chain, join(fixtureDir, 'command.json'), join(fixtureDir, 'ordered.json')], { cwd: root, encoding: 'utf8' });
      if (result.status !== 0) throw new Error(result.stderr);
      entries = [initial, readJson('ordered.json')];
      res.setHeader('Content-Type', 'application/json'); res.end('{"accepted":true}'); return;
    }
    if (url.pathname === '/log' || url.pathname === '/witness') {
      const visible = publishApproval ? entries : [initial];
      const height = Number(url.searchParams.get('after_height') || 0);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ entries: visible.slice(height), tip: visible.at(-1) })); return;
    }
    if (url.pathname === '/package') { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(pkg)); return; }
    const name = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    if (!/^(index\.html|app\.js|style\.css|pkg\/[a-z_]+\.(js|wasm))$/.test(name)) { res.writeHead(404); res.end(); return; }
    res.setHeader('Content-Type', name.endsWith('.wasm') ? 'application/wasm' : name.endsWith('.js') ? 'text/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html');
    res.end(readFileSync(join(buildDir, name)));
  } catch (error) { res.writeHead(400); res.end(String(error)); }
});
await new Promise(resolve => server.listen(4317, 'localhost', resolve));
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1120, height: 1000 } });
const errors = [];
page.on('pageerror', error => errors.push(String(error)));
await page.addInitScript(({ fixedNow }) => {
  Date.now = () => fixedNow * 1000;
  window.entropyCalls = 0;
  const original = crypto.getRandomValues.bind(crypto);
  crypto.getRandomValues = array => { window.entropyCalls++; return original(array); };
  localStorage.setItem('verified_snapshot', '{"height":999999,"approved":true}');
}, { fixedNow: credential.now });
try {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true,
  } });
  await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: {
    credentialId: Buffer.from(credential.rawId, 'hex').toString('base64'), isResidentCredential: false, rpId: 'localhost',
    privateKey: createPrivateKey({ key: credential.jwk, format: 'jwk' }).export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    signCount: 0,
  } });
  await page.goto('http://localhost:4317');
  await page.waitForFunction(() => !document.getElementById('verify').disabled);
  assert.ok(await page.evaluate(() => window.entropyCalls > 0), 'WASM seeded from real browser CSPRNG');
  await page.screenshot({ path: join(artifactDir, `${chain}-initial.png`), fullPage: true });
  for (const [id, path] of [['log-url', '/log'], ['witness-url', '/witness'], ['package-url', '/package'], ['gateway-url', '/approve']]) {
    await page.locator(`#${id}`).fill(`http://localhost:4317${path}`);
  }
  await page.locator('#credential').fill(credential.identity);
  await page.locator('#verify').click();
  await page.waitForFunction(() => !document.getElementById('approve').disabled);
  const displayed = await page.locator('#details').innerText();
  assert.ok(displayed.includes(pkg.intent.intent_id));
  assert.ok(displayed.includes(pkg.asset.symbol));
  assert.ok(!await page.locator('#status').innerText().then(s => s.includes('Approval recorded')));
  await page.screenshot({ path: join(artifactDir, `${chain}-verified.png`), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'no horizontal overflow');
  await page.screenshot({ path: join(artifactDir, `${chain}-mobile.png`), fullPage: true });
  await page.setViewportSize({ width: 1120, height: 1000 });
  await page.locator('#approve').click();
  await page.waitForFunction(() => document.getElementById('status').textContent.includes('Waiting for an ordered approval') || document.getElementById('status').dataset.state === 'blocked');
  assert.notEqual(await page.locator('#status').getAttribute('data-state'), 'blocked', await page.locator('#status').innerText());
  await new Promise(resolve => setTimeout(resolve, 1200));
  assert.ok(submitted, 'WebAuthn assertion reached native executor');
  assert.notEqual(await page.locator('#status').getAttribute('data-state'), 'recorded', 'gateway ack cannot confirm');
  await page.screenshot({ path: join(artifactDir, `${chain}-pending.png`), fullPage: true });
  publishApproval = true;
  await page.waitForFunction(() => document.getElementById('status').dataset.state === 'recorded');
  const command = JSON.parse(submitted);
  assert.equal(command.authority.approve.grant.signature.scheme, 'web_authn_es256');
  assert.equal(command.authority.approve.grant.body.scope.exact_candidate.candidate_id, pkg.candidate.candidate_id);
  assert.ok((await page.locator('#status').innerText()).includes('finalized log at height 4'));
  assert.ok((await page.locator('#details').innerText()).includes('Approvals at review'));
  await page.screenshot({ path: join(artifactDir, `${chain}-recorded.png`), fullPage: true });
  await page.locator('#verify').click();
  await page.waitForFunction(() => document.getElementById('status').dataset.state === 'blocked');
  assert.ok(await page.locator('#operation').isHidden());
  assert.ok(await page.locator('#approve').isDisabled());
  await page.screenshot({ path: join(artifactDir, `${chain}-blocked.png`), fullPage: true });
  // Test the actual WASM public boundary, not a parallel JS implementation.
  const checks = await page.evaluate(async ({ initial, checkpoint, pkg, now, identity }) => {
    const { BrowserClient } = await import('./pkg/oic_approver_client.js');
    const client = new BrowserClient(location.origin, BigInt(now));
    let snapshotRejected = false, bodyRejected = false, staleRejected = false, originRejected = false;
    try { new BrowserClient('https://console.example', BigInt(now)); } catch { originRejected = true; }
    try { client.prepare(JSON.stringify(pkg), identity, BigInt(now)); } catch { snapshotRejected = true; }
    client.apply(JSON.stringify(initial), BigInt(now));
    const before = client.floor();
    let atomicAncestryRejected = true;
    for (let attack = 0; attack < 3; attack++) {
      const forged = structuredClone(checkpoint);
      if (attack === 0) forged.ancestors.shift();
      else if (attack === 1) forged.ancestors.reverse();
      else forged.ancestors[1] = forged.ancestors[1].slice(0, -2) + (forged.ancestors[1].endsWith('00') ? '01' : '00');
      let rejected = false;
      try { client.apply(JSON.stringify(forged), BigInt(now)); } catch { rejected = true; }
      atomicAncestryRejected &&= rejected && client.floor() === before;
    }
    const forged = structuredClone(initial); forged.block = forged.block.slice(0, -2) + (forged.block.endsWith('00') ? '01' : '00');
    try { client.apply(JSON.stringify(forged), BigInt(now)); } catch { bodyRejected = true; }
    try { client.prepare(JSON.stringify(pkg), identity, BigInt(now + 61)); } catch { staleRejected = true; }
    return { snapshotRejected, bodyRejected, staleRejected, originRejected, atomicAncestryRejected };
  }, { initial, checkpoint: readJson('ordered.json'), pkg, now: credential.now, identity: credential.identity });
  assert.deepEqual(checks, { snapshotRejected: true, bodyRejected: true, staleRejected: true, originRejected: true, atomicAncestryRejected: true });
  assert.deepEqual(errors, []);
  const evidence = { chain, browser: browser.version(), realWasm: true, realBrowserEntropy: true, virtualWebAuthn: true, gatewayAckDidNotConfirm: true,
    nativeExecutorAccepted: true, descendantCertificateConfirmedApproval: true, verifiedFinalizationConfirmed: true, ...checks, errors };
  writeFileSync(join(artifactDir, `${chain}-evidence.json`), JSON.stringify(evidence, null, 2));
  console.log(JSON.stringify(evidence));
} finally {
  await browser.close(); await new Promise(resolve => server.close(resolve));
}
