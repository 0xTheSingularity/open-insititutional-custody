// Real WASM + Chromium WebAuthn. Default: fixed-clock certificate fixture.
// --live: forward real NodeApi responses from four TCP Simplex engines.
// Test keys and virtual UV are never hardware attestation or production funds.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createPrivateKey } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const [fixtureDir, buildDir, artifactDir, chain = 'evm', mode] = process.argv.slice(2).map((s, i) => i < 3 ? resolve(s) : s);
const live = mode === '--live';
const root = process.cwd();
const fixtureBin = resolve(process.env.FIXTURE_BIN || 'target/debug/examples/browser-fixture');
const readJson = name => JSON.parse(readFileSync(join(fixtureDir, name), 'utf8'));
const credential = readJson('virtual-credential.json');
const initial = live ? undefined : readJson('initial.json'), pkg = readJson('package.json');
const upstream = live ? readJson('endpoints.json') : undefined;
let entries = [initial], publishApproval = false, submitted;
let frozenTip, latestTip, paginationAttack, forwarded = 0, pages = 0, continuedPages = 0, pageLimitStops = 0, ackStatus;
mkdirSync(artifactDir, { recursive: true });
async function forward(url, method = 'GET', body) {
  const response = await fetch(url, { method, body, headers: {
    Authorization: `Bearer ${upstream.token}`, Origin: 'http://localhost:4317', 'Content-Type': 'application/json',
  }, signal: AbortSignal.timeout(15000) });
  const text = await response.text();
  // Test records intentionally omit the session token.
  writeFileSync(join(artifactDir, `upstream-${++forwarded}.json`), JSON.stringify({ url, method, status: response.status, response: JSON.parse(text) }, null, 2));
  return { status: response.status, text };
}
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost:4317');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Frame-Options', 'DENY');
    if (req.method === 'POST' && url.pathname === '/approve') {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      submitted = Buffer.concat(chunks).toString('utf8');
      writeFileSync(join(fixtureDir, 'command.json'), submitted);
      if (live) {
        // Publication barrier lives ONLY in this test proxy. Native consensus
        // keeps running and journaling while the browser sees its last real tip.
        frozenTip = latestTip;
        const result = await forward(`${upstream.nodes[0]}/v1/node/approvals`, 'POST', submitted);
        ackStatus = result.status;
        res.writeHead(result.status, { 'Content-Type': 'application/json' }); res.end(result.text); return;
      }
      const result = spawnSync(fixtureBin, ['order', chain, join(fixtureDir, 'command.json'), join(fixtureDir, 'ordered.json')], { cwd: root, encoding: 'utf8' });
      if (result.status !== 0) throw new Error(result.stderr);
      entries = [initial, readJson('ordered.json')];
      res.setHeader('Content-Type', 'application/json'); res.end('{"accepted":true}'); return;
    }
    if (url.pathname === '/log' || url.pathname === '/witness') {
      if (paginationAttack) {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ entries: [], tip: latestTip, more: true })); return;
      }
      if (live) {
        if (frozenTip && !publishApproval) {
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ entries: [], tip: frozenTip, more: false })); return;
        }
        const node = upstream.nodes[url.pathname === '/log' ? 0 : 1];
        const result = await forward(`${node}/v1/node/log${url.search}`);
        if (result.status === 200) {
          const record = JSON.parse(result.text);
          latestTip = record.tip; pages++; if (record.more) continuedPages++;
        }
        res.writeHead(result.status, { 'Content-Type': 'application/json' }); res.end(result.text); return;
      }
      const visible = publishApproval ? entries : [initial];
      const height = Number(url.searchParams.get('after_height') || 0);
      latestTip = visible.at(-1);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ entries: visible.slice(height), tip: latestTip, more: false })); return;
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
await page.addInitScript(({ fixedNow, live }) => {
  if (!live) Date.now = () => fixedNow * 1000;
  window.entropyCalls = 0;
  const original = crypto.getRandomValues.bind(crypto);
  crypto.getRandomValues = array => { window.entropyCalls++; return original(array); };
  localStorage.setItem('verified_snapshot', '{"height":999999,"approved":true}');
}, { fixedNow: credential.now, live });
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
  // A cold live installation can have >64 certified pages already. Exercise
  // the UI's explicit bounded-resume action instead of raising/removing its cap.
  for (let attempt = 0; attempt < 128; attempt++) {
    await page.locator('#verify').click();
    await page.waitForFunction(() => !document.getElementById('verify').disabled);
    if (await page.locator('#approve').isEnabled()) break;
    assert.ok((await page.locator('#status').innerText()).includes('exceeds 64 pages'), await page.locator('#status').innerText());
    assert.ok(await page.locator('#operation').isHidden());
    if (++pageLimitStops === 1) await page.screenshot({ path: join(artifactDir, `${chain}-page-limit.png`), fullPage: true });
  }
  assert.ok(await page.locator('#approve').isEnabled(), 'bounded explicit resume must reach current verified history');
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
  if (live) {
    assert.equal(ackStatus, 202, 'native HTTP accepts only local enqueue');
    await page.waitForFunction(() => document.getElementById('status').dataset.state !== 'blocked');
    const deadline = Date.now() + 60000;
    while (!existsSync(join(fixtureDir, 'approval-observed.json'))) {
      assert.ok(Date.now() < deadline, 'four actual engines must durably order approval');
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    const proof = readJson('approval-observed.json');
    assert.equal(proof.replicas.length, 4);
    for (const replica of proof.replicas) {
      assert.deepEqual(replica.grants[pkg.intent.intent_id][credential.identity].grant, JSON.parse(submitted).authority.approve.grant, 'exact browser grant in every synced replica');
    }
    writeFileSync(join(artifactDir, 'approval-observed.json'), JSON.stringify(proof, null, 2));
  }
  assert.notEqual(await page.locator('#status').getAttribute('data-state'), 'recorded', 'gateway ack cannot confirm');
  await page.screenshot({ path: join(artifactDir, `${chain}-pending.png`), fullPage: true });
  publishApproval = true;
  await page.waitForFunction(() => document.getElementById('status').dataset.state === 'recorded');
  const command = JSON.parse(submitted);
  assert.equal(command.authority.approve.grant.signature.scheme, 'web_authn_es256');
  assert.equal(command.authority.approve.grant.body.scope.exact_candidate.candidate_id, pkg.candidate.candidate_id);
  assert.ok((await page.locator('#status').innerText()).includes(live ? 'certificate-verified finalized log at height' : 'finalized log at height 4'));
  assert.ok((await page.locator('#details').innerText()).includes('Approvals at review'));
  await page.screenshot({ path: join(artifactDir, `${chain}-recorded.png`), fullPage: true });
  await page.locator('#verify').click();
  await page.waitForFunction(() => document.getElementById('status').dataset.state === 'blocked');
  assert.ok(await page.locator('#operation').isHidden());
  assert.ok(await page.locator('#approve').isDisabled());
  await page.screenshot({ path: join(artifactDir, `${chain}-blocked.png`), fullPage: true });
  // Test the actual WASM public boundary, not a parallel JS implementation.
  const checks = live ? {} : await page.evaluate(async ({ initial, checkpoint, pkg, now, identity }) => {
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
  }, { initial, checkpoint: live ? undefined : readJson('ordered.json'), pkg, now: credential.now, identity: credential.identity });
  if (!live) assert.deepEqual(checks, { snapshotRejected: true, bodyRejected: true, staleRejected: true, originRejected: true, atomicAncestryRejected: true });
  paginationAttack = true;
  await page.locator('#verify').click();
  await page.waitForFunction(() => document.getElementById('status').textContent.includes('pagination did not advance'));
  assert.ok(await page.locator('#operation').isHidden());
  assert.ok(await page.locator('#approve').isDisabled());
  assert.deepEqual(errors, []);
  const evidence = { chain, browser: browser.version(), realWasm: true, realBrowserEntropy: true, virtualWebAuthn: true, gatewayAckDidNotConfirm: true,
    realSimplex: live, actualHttpResponses: live ? forwarded : 0, verifiedPages: pages, continuedPages, pageLimitStops, noProgressPaginationRejected: true,
    nativeExecutorAccepted: true, verifiedFinalizationConfirmed: true, ...checks, errors };
  writeFileSync(join(artifactDir, `${chain}-evidence.json`), JSON.stringify(evidence, null, 2));
  console.log(JSON.stringify(evidence));
} catch (error) {
  writeFileSync(join(artifactDir, `${chain}-failure.txt`), `${error.stack}\n${await page.locator('body').innerText()}`);
  await page.screenshot({ path: join(artifactDir, `${chain}-failure.png`), fullPage: true });
  throw error;
} finally {
  if (live) writeFileSync(join(fixtureDir, 'stop'), 'browser finished');
  await browser.close(); await new Promise(resolve => server.close(resolve));
}
