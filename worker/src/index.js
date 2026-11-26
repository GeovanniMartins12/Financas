// Servidor do app Finanças — cofre cifrado + agendador de notificações.
//
// O servidor NUNCA vê seus dados: o app cifra tudo no iPhone (AES-256-GCM, chave
// derivada da sua senha) antes de enviar. Aqui só ficam blocos ilegíveis, a agenda de
// avisos (datas + textos cifrados) e as assinaturas de push.
//
// Rotas (todas sob /api):
//   GET  /api/meta                     -> {configured, salt, iter}
//   POST /api/setup     {salt,iter,authHash}  (só uma vez)
//   GET  /api/vapid                    -> {publicKey}
//   GET  /api/docs          [auth]     -> {docs:{id:{u,iv,c}}}
//   POST /api/docs          [auth]     {docs:[{id,u,iv,c}]} -> {docs:{id:{u,...}}}
//   POST /api/schedule      [auth]     {items:[{on,iv,c}]}
//   POST /api/subscribe     [auth]     {subscription, device}
//   POST /api/unsubscribe   [auth]     {endpoint}
//   POST /api/test          [auth]     -> push de teste (texto genérico)
// Cron diário: 9h (avisos de contas) e 21h (lembrete de lançar gastos), horário de Brasília.

const TZ = 'America/Sao_Paulo';
const enc = new TextEncoder();

// ---------- utilidades ----------
export const b64u = buf => {
  const b = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
export const unb64u = s => {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '=';
  const bin = atob(s), out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const concat = (...arrs) => {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0)); let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length } return out;
};
const sha256b64u = async s => b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s))));
function safeEqual(a, b) {
  a = String(a || ''); b = String(b || '');
  if (a.length !== b.length || !a.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const B64U_RE = /^[A-Za-z0-9_-]+$/;
const isB64u = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && B64U_RE.test(s);

function corsFor(req, env) {
  const origin = req.headers.get('Origin') || '';
  const allowed = String(env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const ok = !allowed.length || allowed.includes(origin);
  return {
    'Access-Control-Allow-Origin': ok ? (origin || '*') : 'null',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization,Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin'
  };
}
const jsonRes = (cors, data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...cors }
});

const getJSON = async (env, key, fb) => { const v = await env.FIN.get(key, 'json'); return v == null ? fb : v };
const putJSON = (env, key, v) => env.FIN.put(key, JSON.stringify(v));

// ---------- VAPID ----------
async function vapidKeys(env) {
  let k = await getJSON(env, 'vapid', null);
  if (!k) {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    k = { publicKey: b64u(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))), jwk: await crypto.subtle.exportKey('jwk', pair.privateKey) };
    await putJSON(env, 'vapid', k);
  }
  return k;
}
export async function vapidAuth(endpoint, keys, subject) {
  const aud = new URL(endpoint).origin;
  const h = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const p = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject })));
  const priv = await crypto.subtle.importKey('jwk', keys.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, enc.encode(h + '.' + p));
  return `vapid t=${h}.${p}.${b64u(new Uint8Array(sig))}, k=${keys.publicKey}`;
}

// ---------- cifra do push (RFC 8291 / aes128gcm) ----------
async function hkdf(salt, ikm, info, len) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, len * 8));
}
export async function encryptPayload(sub, plaintext) {
  const uaPublic = unb64u(sub.keys.p256dh), authSecret = unb64u(sub.keys.auth);
  const as = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', as.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, as.privateKey, 256));
  const ikm = await hkdf(authSecret, ecdh, concat(enc.encode('WebPush: info\0'), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, concat(enc.encode(plaintext), new Uint8Array([2]))));
  return concat(salt, new Uint8Array([0, 0, 16, 0]), new Uint8Array([65]), asPublic, ct);
}
async function sendPush(env, sub, message, fetchImpl = fetch) {
  const keys = await vapidKeys(env);
  const res = await fetchImpl(sub.endpoint, {
    method: 'POST',
    headers: {
      Authorization: await vapidAuth(sub.endpoint, keys, env.VAPID_SUBJECT || 'mailto:financas@example.com'),
      'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '86400', Urgency: 'high'
    },
    body: await encryptPayload(sub, JSON.stringify(message))
  });
  return res.status;
}
export async function pushAll(env, message, fetchImpl) {
  const subs = await getJSON(env, 'subs', []);
  let sent = 0; const keep = [];
  for (const s of subs) {
    let st = 0; try { st = await sendPush(env, s, message, fetchImpl) } catch (e) { st = 0 }
    if (st === 404 || st === 410) continue;
    keep.push(s); if (st >= 200 && st < 300) sent++;
  }
  if (keep.length !== subs.length) await putJSON(env, 'subs', keep);
  return { sent, devices: keep.length };
}

// ---------- agenda diária ----------
export function todayIn(tz, now = new Date()) {
  const p = new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(now);
  const g = t => p.find(x => x.type === t).value;
  return `${g('year')}-${g('month')}-${g('day')}`;
}
// slot '09' = avisos de contas (12:00 UTC); slot '21' = lembrete noturno (00:00 UTC = 21h do dia anterior em Brasília)
export async function runDaily(env, now = new Date(), fetchImpl, slot = '09') {
  const today = todayIn(TZ, now);
  const sched = await getJSON(env, 'sched', { items: [] });
  const due = (sched.items || []).filter(i => i.on === today && (i.at || '09') === slot);
  const sentLog = await getJSON(env, 'sentlog', {});
  const key = 'last' + slot, last = sentLog[key] || (slot === '09' ? sentLog.last : '');
  if (!due.length || last === today) return { today, slot, due: due.length, sent: 0 };
  let sent = 0;
  for (const item of due) sent += (await pushAll(env, { iv: item.iv, c: item.c }, fetchImpl)).sent;
  if (sent) { sentLog[key] = today; delete sentLog.last; await putJSON(env, 'sentlog', sentLog) }
  return { today, slot, due: due.length, sent };
}

// ---------- autenticação com bloqueio por tentativas ----------
async function checkAuth(req, env) {
  const meta = await getJSON(env, 'meta', null);
  if (!meta) return 'not_configured';
  const fails = await getJSON(env, 'fails', { n: 0, t: 0 });
  const now = Date.now();
  if (fails.n >= 10 && now - fails.t < 3600e3) return 'locked';
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  if (token && safeEqual(await sha256b64u(token), meta.authHash)) {
    if (fails.n) await putJSON(env, 'fails', { n: 0, t: 0 });
    return 'ok';
  }
  await putJSON(env, 'fails', { n: now - fails.t > 3600e3 ? 1 : fails.n + 1, t: now - fails.t > 3600e3 ? now : fails.t || now });
  return 'unauthorized';
}

const MAX_DOC = 2 * 1024 * 1024, MAX_STATE = 20 * 1024 * 1024;

export default {
  async fetch(req, env, ctx, fetchImpl) {
    const cors = corsFor(req, env);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    const p = new URL(req.url).pathname.replace(/\/+$/, '');
    const J = (d, s) => jsonRes(cors, d, s);
    try {
      if (p === '/api/meta') {
        const m = await getJSON(env, 'meta', null);
        return J(m ? { configured: true, salt: m.salt, iter: m.iter } : { configured: false });
      }
      if (p === '/api/vapid') return J({ publicKey: (await vapidKeys(env)).publicKey });
      if (p === '/api/setup' && req.method === 'POST') {
        if (await getJSON(env, 'meta', null)) return J({ error: 'already_configured' }, 403);
        const { salt, iter, authHash } = await req.json();
        if (!isB64u(salt, 64) || !isB64u(authHash, 64) || !(iter >= 100000 && iter <= 5000000)) return J({ error: 'bad_request' }, 400);
        await putJSON(env, 'meta', { salt, iter, authHash, created: Date.now() });
        return J({ ok: true });
      }
      if (!p.startsWith('/api/')) return J({ error: 'not_found' }, 404);

      const a = await checkAuth(req, env);
      if (a === 'not_configured') return J({ error: 'not_configured' }, 409);
      if (a === 'locked') return J({ error: 'locked' }, 429);
      if (a !== 'ok') return J({ error: 'unauthorized' }, 401);

      if (p === '/api/docs' && req.method === 'GET') return J({ docs: (await getJSON(env, 'docs', {})) });
      if (p === '/api/docs' && req.method === 'POST') {
        const { docs } = await req.json();
        if (!Array.isArray(docs)) return J({ error: 'bad_request' }, 400);
        const all = await getJSON(env, 'docs', {}); const out = {}; let changed = false;
        for (const d of docs) {
          if (!d || !isB64u(d.id, 64) || typeof d.u !== 'number' || !isB64u(d.iv, 32) || !isB64u(d.c, MAX_DOC)) continue;
          const cur = all[d.id];
          // Controle de versão: o app informa a versão que viu por último (base).
          // Se outro aparelho gravou antes, recusa; o app baixa, mescla e reenvia.
          const ok = ('base' in d) ? (cur ? d.base === cur.u : d.base == null) : (!cur || d.u >= cur.u);
          if (ok) { all[d.id] = { u: d.u, iv: d.iv, c: d.c }; changed = true }
          out[d.id] = { u: all[d.id].u };
        }
        if (changed) {
          if (JSON.stringify(all).length > MAX_STATE) return J({ error: 'too_large' }, 413);
          await putJSON(env, 'docs', all);
        }
        return J({ docs: out });
      }
      if (p === '/api/schedule' && req.method === 'POST') {
        const { items } = await req.json();
        if (!Array.isArray(items) || items.length > 400) return J({ error: 'bad_request' }, 400);
        const clean = items.filter(i => i && /^\d{4}-\d{2}-\d{2}$/.test(i.on) && isB64u(i.iv, 32) && isB64u(i.c, 6000)).map(i => ({ on: i.on, at: i.at === '21' ? '21' : '09', iv: i.iv, c: i.c }));
        await putJSON(env, 'sched', { items: clean, at: Date.now() });
        return J({ ok: true, items: clean.length });
      }
      if (p === '/api/subscribe' && req.method === 'POST') {
        const { subscription: s, device } = await req.json();
        if (!s || typeof s.endpoint !== 'string' || !/^https:\/\//.test(s.endpoint) || !s.keys || !isB64u(s.keys.p256dh, 200) || !isB64u(s.keys.auth, 64)) return J({ error: 'bad_subscription' }, 400);
        const subs = (await getJSON(env, 'subs', [])).filter(x => x.endpoint !== s.endpoint);
        subs.push({ endpoint: s.endpoint, keys: { p256dh: s.keys.p256dh, auth: s.keys.auth }, device: String(device || '').slice(0, 60), at: Date.now() });
        await putJSON(env, 'subs', subs.slice(-10));
        return J({ ok: true, devices: Math.min(subs.length, 10) });
      }
      if (p === '/api/unsubscribe' && req.method === 'POST') {
        const { endpoint } = await req.json();
        await putJSON(env, 'subs', (await getJSON(env, 'subs', [])).filter(x => x.endpoint !== endpoint));
        return J({ ok: true });
      }
      if (p === '/api/test' && req.method === 'POST') {
        return J(await pushAll(env, { title: 'Finanças', body: 'Notificações funcionando. Os avisos de vencimento chegam às 9h.' }, fetchImpl));
      }
      return J({ error: 'not_found' }, 404);
    } catch (e) {
      return J({ error: 'server_error' }, 500);
    }
  },
  async scheduled(event, env, ctx) { ctx.waitUntil(runDaily(env, new Date(), undefined, event.cron === '0 0 * * *' ? '21' : '09')) }
};
