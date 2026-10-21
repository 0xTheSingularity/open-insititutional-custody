import init, { BrowserClient } from './pkg/oic_approver_client.js';

const $ = id => document.getElementById(id);
const now = () => BigInt(Math.floor(Date.now() / 1000));
const unhex = text => {
  text = text.replace(/^0x/, '');
  if (typeof text !== 'string' || !/^(?:[0-9a-f]{2})+$/i.test(text)) throw new Error('Invalid verified byte encoding');
  return Uint8Array.from(text.match(/../g), byte => parseInt(byte, 16));
};
let client, prepared, expiryTimer, busy = false;
function status(text, state = '') { $('status').textContent = text; $('status').dataset.state = state; }
function blocked(error) {
  clearTimeout(expiryTimer);
  prepared = undefined;
  $('approve').disabled = true;
  $('operation').hidden = true;
  status(`Approval blocked: ${String(error)}. Refresh verified records or contact your institution.`, 'blocked');
}
function endpoint(id) {
  const url = new URL($(id).value);
  if (url.username || url.password || (url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === 'localhost' && location.hostname === 'localhost'))) {
    throw new Error('Endpoints require HTTPS (localhost HTTP is development only)');
  }
  return url;
}
async function read(url) {
  const response = await fetch(url, { credentials: 'include', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`Read failed (${response.status})`);
  const reader = response.body.getReader();
  let length = 0; const chunks = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > 10 * 1024 * 1024) { await reader.cancel(); throw new Error('Artifact exceeds read limit'); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}
async function follow(url) {
  // Entries are atomic certified checkpoints with optional ancestors. The tip
  // marker is only the certified block/certificate, never a state snapshot.
  const floor = JSON.parse(client.floor());
  url.searchParams.set('after_height', String(floor.height));
  url.searchParams.set('after_digest', floor.digest);
  const log = JSON.parse(await read(url));
  if (!Array.isArray(log.entries) || log.entries.length > 256 || !log.tip) throw new Error('Invalid or oversized finalized log suffix');
  for (const entry of log.entries) client.apply(JSON.stringify(entry), now());
  const { block, finalization } = log.tip;
  client.apply(JSON.stringify({ block, finalization }), now());
  return JSON.parse(client.floor());
}
async function refresh() {
  const primary = endpoint('log-url'), second = endpoint('witness-url');
  if (primary.href === second.href) throw new Error('Configure a distinct second witness endpoint');
  const first = await follow(primary);
  const secondFloor = await follow(second);
  // A second source may advance the verified log. A source withholding a
  // newer certificate is caught by replay or the locally enforced age limit.
  return secondFloor.height >= first.height ? secondFloor : first;
}
function show(result) {
  const d = result.display;
  const fields = [
    ['Network / profile', `${d.network_id} / ${d.chain_profile_id}`],
    ['Operation', d.operation_kind], ['Asset', `${d.asset_symbol_from_registry} (${d.asset_identity})`],
    ['Amount', `${d.amount_display} (${d.amount_base_units} base units; ${d.decimals} decimals)`],
    ['Beneficiary', d.recipient_address_display], ['Registry destination', `${d.destination_display_name} / ${d.destination_id} v${d.destination_version}`],
    ['From wallet', d.wallet_address_display], ['Maximum native fee', `${d.max_native_fee_base_units} base units`],
    ['Authority changes', 'None; pinned adapters admit direct transfers only'], ['Purpose', d.purpose],
    ['Intent', d.intent_id], ['Candidate', `${d.candidate_id} / revision ${d.candidate_revision}`],
    ['Policy', `${d.policy_id} / epoch ${d.policy_epoch}`], ['Log at review', `Height ${result.floor.height}; ${result.view_age_seconds}s old at review`],
    ['Approvals at review', String(result.recorded_approvals)], ['Preview hash', d.preview_hash], ['Grant challenge', result.challenge],
  ];
  $('details').replaceChildren(...fields.flatMap(([label, value]) => {
    const dt = document.createElement('dt'), dd = document.createElement('dd');
    dt.textContent = label; dd.textContent = value; return [dt, dd];
  }));
  $('mode').textContent = result.development ? 'Development installation. Simulator evidence and virtual authenticators are not valid for production funds.' : 'Institution-provisioned installation. Review every field before approving.';
  $('warnings').textContent = d.warnings.join('\n');
  $('operation').hidden = false;
  $('approve').disabled = false;
  const deadline = BigInt(Math.min(result.expires_at, result.view_expires_at));
  expiryTimer = setTimeout(() => blocked('Displayed grant or verified view expired'), Math.max(0, Number(deadline - now())) * 1000);
}
$('load').addEventListener('submit', async event => {
  event.preventDefault();
  if (busy) return;
  busy = true; $('verify').disabled = true;
  try {
    prepared = undefined; clearTimeout(expiryTimer); $('approve').disabled = true; $('operation').hidden = true;
    status('Verifying certificates and reexecuting finalized records…');
    endpoint('gateway-url');
    await refresh();
    prepared = JSON.parse(client.prepare(await read(endpoint('package-url')), $('credential').value, now()));
    show(prepared);
    status('Operation verified. Approval has not been signed or recorded.');
  } catch (error) { blocked(error); }
  finally { busy = false; $('verify').disabled = false; }
});
$('approve').addEventListener('click', async () => {
  if (busy || !prepared) return;
  busy = true; $('approve').disabled = true; $('verify').disabled = true;
  try {
    // Never use a server-supplied challenge, role, grant body, RP or key.
    const credential = await navigator.credentials.get({ publicKey: {
      challenge: unhex(prepared.challenge), rpId: prepared.rp_id,
      allowCredentials: [{ type: 'public-key', id: unhex(prepared.raw_credential_id) }],
      userVerification: 'required', timeout: 60000,
    } });
    if (!credential || credential.type !== 'public-key') throw new Error('No WebAuthn assertion returned');
    const response = credential.response;
    const command = client.assertion(new Uint8Array(credential.rawId), new Uint8Array(response.authenticatorData),
      new Uint8Array(response.clientDataJSON), new Uint8Array(response.signature), now());
    status('Assertion verified locally. Waiting for an ordered approval; gateway acknowledgement is not confirmation.');
    const sent = await fetch(endpoint('gateway-url'), { method: 'POST', credentials: 'include', redirect: 'error',
      headers: { 'Content-Type': 'application/json' }, body: command, signal: AbortSignal.timeout(15000) });
    if (!sent.ok) throw new Error(`Gateway rejected approval (${sent.status}); reconcile the finalized log before retrying`);
    // No automatic resubmission after an ambiguous network failure.
    for (let attempt = 0; attempt < 30; attempt++) {
      await refresh();
      if (client.confirmed(now())) {
        clearTimeout(expiryTimer); prepared = undefined;
        const floor = JSON.parse(client.floor());
        status(`Approval recorded. The exact passkey grant is in the certificate-verified finalized log at height ${floor.height}. Details above describe the operation and state at review.`, 'recorded');
        return;
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    throw new Error('Finalized approval not observed. Submission may still be pending; reconcile before retrying');
  } catch (error) { blocked(error); }
  finally { busy = false; $('verify').disabled = false; }
});
try {
  if (!isSecureContext || !navigator.credentials || !globalThis.PublicKeyCredential) throw new Error('Secure context and WebAuthn-capable browser required');
  await init();
  client = new BrowserClient(location.origin, now());
  $('verify').disabled = false;
  status('Installed verifier loaded. Fetch verified records to begin.');
} catch (error) { blocked(error); }
