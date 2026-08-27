import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const publicDir = path.join(root, 'public');
const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL || '';
const AI_BASE_URL = process.env.AI_BASE_URL || '';
const AI_API_KEY = process.env.AI_API_KEY || '';
const AI_MODEL = process.env.AI_MODEL || '';
const AI_MODE = (process.env.AI_MODE || 'DEMO').toUpperCase();
const SESSION_TTL_DAYS = Number(process.env.SESSION_TTL_DAYS || 30);
const WORKER_ID = process.env.WORKER_ID || `worker-${process.pid}`;
const WORKER_POLL_MS = Number(process.env.WORKER_POLL_MS || 750);
const MAX_AGENT_RETRIES = Number(process.env.MAX_AGENT_RETRIES || 2);
const WEB_SEARCH_URL = process.env.WEB_SEARCH_URL || '';
const WEB_SEARCH_API_KEY = process.env.WEB_SEARCH_API_KEY || '';
const BILLING_MODE = (process.env.BILLING_MODE || 'DEMO').toUpperCase();
const CURRENCY = process.env.CURRENCY || 'BRL';
const OWNER_EMAIL = (process.env.OWNER_EMAIL || '').trim().toLowerCase();
const NODE_ENV = (process.env.NODE_ENV || 'development').toLowerCase();
const PUBLIC_ORIGIN = (process.env.PUBLIC_ORIGIN || '').replace(/\/$/, '');
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES || 1024 * 1024);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000);
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 120);
const rateBuckets = new Map();

if (!DATABASE_URL) throw new Error('DATABASE_URL não configurada.');
if (NODE_ENV === 'production') {
  if (AI_MODE !== 'LIVE') throw new Error('Produção exige AI_MODE=LIVE.');
  if (BILLING_MODE === 'DEMO') throw new Error('Produção exige BILLING_MODE diferente de DEMO.');
  if (!PUBLIC_ORIGIN || !PUBLIC_ORIGIN.startsWith('https://')) throw new Error('Produção exige PUBLIC_ORIGIN HTTPS.');
  if (!OWNER_EMAIL || OWNER_EMAIL.endsWith('@example.com')) throw new Error('Produção exige OWNER_EMAIL real.');
}

const pool = new Pool({ connectionString: DATABASE_URL });

function securityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    ...(NODE_ENV === 'production' ? { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } : {})
  };
}

function json(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...securityHeaders(),
    ...extraHeaders
  });
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  const declared = Number(req.headers['content-length'] || 0);
  if (declared > MAX_BODY_BYTES) throw new Error('Payload excede o limite permitido.');
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) throw new Error('Payload excede o limite permitido.');
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { throw new Error('JSON inválido.'); }
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  const { hash } = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(expectedHash, 'hex'));
}

function newToken() {
  return crypto.randomBytes(32).toString('hex');
}

function sessionCookie(token, maxAgeSeconds) {
  const secure = NODE_ENV === 'production' ? '; Secure' : '';
  return `nexus_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure}`;
}

function clearSessionCookie() {
  const secure = NODE_ENV === 'production' ? '; Secure' : '';
  return `nexus_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}

function parseCookie(header = '') {
  const out = {};
  for (const item of header.split(';')) {
    const idx = item.indexOf('=');
    if (idx > 0) out[item.slice(0, idx).trim()] = decodeURIComponent(item.slice(idx + 1).trim());
  }
  return out;
}

async function getAuth(req) {
  const token = parseCookie(req.headers.cookie || '').nexus_session;
  if (!token) return null;
  const { rows } = await pool.query(`
    SELECT s.user_id, s.expires_at, u.name, u.email, u.status,
           o.id AS organization_id, o.name AS organization_name, m.role
    FROM auth_sessions s
    JOIN users u ON u.id = s.user_id
    JOIN memberships m ON m.user_id = u.id AND m.status = 'ACTIVE'
    JOIN organizations o ON o.id = m.organization_id AND o.status = 'ACTIVE'
    WHERE s.token_hash = encode(digest($1, 'sha256'), 'hex')
      AND s.expires_at > now()
    LIMIT 1`, [token]);
  if (!rows[0]) return null;
  return {
    userId: rows[0].user_id,
    name: rows[0].name,
    email: rows[0].email,
    organizationId: rows[0].organization_id,
    organizationName: rows[0].organization_name,
    role: rows[0].role
  };
}

function requireAuth(auth, res) {
  if (!auth) { json(res, 401, { error: 'Autenticação necessária.' }); return false; }
  return true;
}

function requireOwner(auth, res) {
  if (!requireAuth(auth, res)) return false;
  if (!OWNER_EMAIL || String(auth.email).toLowerCase() !== OWNER_EMAIL) {
    json(res, 403, { error: 'Acesso restrito ao proprietário da plataforma.' });
    return false;
  }
  return true;
}

function slugify(value) {
  return value.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '').slice(0, 48) || 'workspace';
}

async function uniqueSlug(base) {
  const baseSlug = slugify(base);
  let candidate = baseSlug;
  for (let i = 1; i < 100; i++) {
    const { rowCount } = await pool.query('SELECT 1 FROM organizations WHERE slug=$1 LIMIT 1', [candidate]);
    if (!rowCount) return candidate;
    candidate = `${baseSlug}-${i + 1}`;
  }
  return `${baseSlug}-${Date.now()}`;
}


function billingPlans() {
  return [
    { code: 'FREE', name: 'Free', price: 0, interval: 'month', credits: 50, features: ['basic_workspace','basic_agents'] },
    { code: 'STARTER', name: 'Starter', price: 29.90, interval: 'month', credits: 500, features: ['standard_agents','more_missions'] },
    { code: 'PRO', name: 'Pro', price: 79.90, interval: 'month', credits: 2000, features: ['advanced_agents','larger_context','advanced_missions'] },
    { code: 'BUSINESS', name: 'Business', price: 199.90, interval: 'month', credits: 7000, features: ['team','shared_projects','analytics'] }
  ];
}

function findPlan(code) { return billingPlans().find(p => p.code === String(code || '').toUpperCase()) || null; }

async function ensureBillingSeed(client) {
  for (const plan of billingPlans()) {
    await client.query(`INSERT INTO plans (code,name,price,currency,interval,credits,features,active) VALUES ($1,$2,$3,$4,$5,$6,$7,true) ON CONFLICT (code) DO UPDATE SET name=EXCLUDED.name, price=EXCLUDED.price, currency=EXCLUDED.currency, interval=EXCLUDED.interval, credits=EXCLUDED.credits, features=EXCLUDED.features, active=true`, [plan.code, plan.name, plan.price, CURRENCY, plan.interval, plan.credits, JSON.stringify(plan.features)]);
  }
}

async function getSubscriptionState(client, organizationId) {
  const { rows } = await client.query(`SELECT s.id,s.plan_id,s.status,s.current_period_start,s.current_period_end,p.code,p.name,p.price,p.currency,p.interval,p.credits,p.features FROM subscriptions s JOIN plans p ON p.id=s.plan_id WHERE s.organization_id=$1 ORDER BY s.created_at DESC LIMIT 1`, [organizationId]);
  return rows[0] || null;
}

async function getCreditBalance(client, organizationId) {
  const { rows } = await client.query(`SELECT COALESCE(SUM(amount),0)::numeric AS balance FROM credit_ledger WHERE organization_id=$1`, [organizationId]);
  return Number(rows[0]?.balance || 0);
}

async function createDemoCheckout(client, organizationId, userId, planCode) {
  const plan = findPlan(planCode);
  if (!plan || plan.code === 'FREE') throw new Error('Plano pago inválido para checkout.');
  await ensureBillingSeed(client);
  const checkoutId = crypto.randomUUID();
  await client.query(`INSERT INTO checkout_sessions (id,organization_id,user_id,plan_id,status,provider,created_at) VALUES ($1,$2,$3,(SELECT id FROM plans WHERE code=$4),'OPEN','DEMO',now())`, [checkoutId, organizationId, userId, plan.code]);
  return { checkoutId, provider: 'DEMO', status: 'OPEN', plan };
}

async function activateDemoSubscription(client, organizationId, userId, checkoutId) {
  const checkout = (await client.query(`SELECT c.*,p.code,p.name,p.price,p.currency,p.interval,p.credits,p.features FROM checkout_sessions c JOIN plans p ON p.id=c.plan_id WHERE c.id=$1 AND c.organization_id=$2 FOR UPDATE`, [checkoutId, organizationId])).rows[0];
  if (!checkout) throw new Error('Checkout não encontrado.');
  if (checkout.status === 'COMPLETED') return checkout;
  const existing = await client.query(`SELECT id FROM subscriptions WHERE organization_id=$1 AND status='ACTIVE' LIMIT 1`, [organizationId]);
  const start = new Date();
  const end = new Date(start); end.setMonth(end.getMonth()+1);
  let subscriptionId;
  if (existing.rowCount) {
    subscriptionId = existing.rows[0].id;
    await client.query(`UPDATE subscriptions SET plan_id=$1,status='ACTIVE',current_period_start=$2,current_period_end=$3,updated_at=now() WHERE id=$4`, [checkout.plan_id,start,end,subscriptionId]);
  } else {
    subscriptionId = (await client.query(`INSERT INTO subscriptions (organization_id,plan_id,status,current_period_start,current_period_end,created_at,updated_at) VALUES ($1,$2,'ACTIVE',$3,$4,now(),now()) RETURNING id`, [organizationId,checkout.plan_id,start,end])).rows[0].id;
  }
  const payment = (await client.query(`INSERT INTO payments (organization_id,subscription_id,amount,currency,status,provider,payment_reference,created_at,paid_at) VALUES ($1,$2,$3,$4,'PAID','DEMO',$5,now(),now()) RETURNING id`, [organizationId,subscriptionId,checkout.price,checkout.currency,`demo_payment_${crypto.randomUUID()}`])).rows[0];
  const grantKey = `subscription:${subscriptionId}:${start.toISOString().slice(0,10)}`;
  await client.query(`INSERT INTO credit_ledger (organization_id,type,amount,reference,balance_after,created_at) SELECT $1,'GRANT',$2,$3,COALESCE((SELECT SUM(amount) FROM credit_ledger WHERE organization_id=$1),0)+$2,now() WHERE NOT EXISTS (SELECT 1 FROM credit_ledger WHERE organization_id=$1 AND reference=$3)`, [organizationId,checkout.credits,grantKey]);
  await client.query(`UPDATE checkout_sessions SET status='COMPLETED',completed_at=now(),updated_at=now() WHERE id=$1`, [checkoutId]);
  return { subscriptionId, paymentId: payment.id, plan: { code: checkout.code, name: checkout.name, credits: checkout.credits } };
}

async function enforceMissionCredits(client, organizationId) {
  const balance = await getCreditBalance(client, organizationId);
  const required = 25;
  if (balance < required) return { allowed: false, balance, required };
  return { allowed: true, balance, required };
}

function classify(objective) {
  const text = objective.toLowerCase();
  const complexWords = ['estratégia', 'plano', 'lançamento', 'campanha', 'aumentar vendas', 'crescer', 'marketing', 'negócio'];
  const needsResearch = ['concorrentes', 'mercado', 'tendências', 'pesquisa', 'pesquisar'].some(w => text.includes(w));
  const complex = complexWords.some(w => text.includes(w)) || text.length > 90;
  return { type: complex ? 'COMPLEX_MISSION' : 'SIMPLE', domain: needsResearch ? 'RESEARCH' : 'GENERAL', requiresResearch: needsResearch };
}

function makePlan(objective, classification) {
  const lower = objective.toLowerCase();
  const tasks = [{ title: 'Entender objetivo e contexto', agent: 'GENERAL' }];
  if (classification.requiresResearch) tasks.push({ title: 'Pesquisar informações relevantes', agent: 'RESEARCH' });
  tasks.push(lower.match(/conteúdo|instagram|tiktok|post|vídeo/) ? { title: 'Criar estratégia e conteúdo', agent: 'CONTENT' } : { title: 'Construir estratégia e ações', agent: 'STRATEGY' });
  if (lower.match(/vendas|vender|marketing|campanha|lançamento/)) tasks.push({ title: 'Transformar estratégia em ações de marketing', agent: 'MARKETING' });
  tasks.push({ title: 'Definir métricas e próximos passos', agent: 'ANALYTICS' });
  tasks.push({ title: 'Consolidar entrega final', agent: 'GENERAL' });
  return tasks;
}

async function callAI(prompt, meta = {}) {
  const started = Date.now();
  if (AI_MODE !== 'LIVE') {
    return { content: null, usage: {}, mode: 'DEMO', provider: null, model: null, durationMs: Date.now() - started };
  }
  if (!AI_BASE_URL || !AI_API_KEY || !AI_MODEL) throw new Error('IA em modo LIVE, mas AI_BASE_URL, AI_API_KEY ou AI_MODEL não está configurado.');
  const url = `${AI_BASE_URL.replace(/\/$/, '')}/chat/completions`;
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${AI_API_KEY}` },
    body: JSON.stringify({ model: AI_MODEL, messages: [
      { role: 'system', content: 'Você é o NEXUS ONE. Transforme objetivos em trabalho executável. Seja objetivo, prático e estruturado. Não invente fatos.' },
      { role: 'user', content: prompt }
    ], temperature: 0.2 })
  });
  if (!r.ok) throw new Error(`Falha no provedor de IA (${r.status}).`);
  const data = await r.json();
  const content = data?.choices?.[0]?.message?.content;
  if (!content) throw new Error('O provedor de IA não retornou conteúdo.');
  const usage = data?.usage || {};
  return {
    content,
    usage,
    mode: 'LIVE',
    provider: new URL(AI_BASE_URL).hostname,
    model: AI_MODEL,
    durationMs: Date.now() - started,
    taskId: meta.taskId,
    agent: meta.agent
  };
}

function tryParseJSON(value) {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value); } catch {}
  const match = value.match(/```json\s*([\s\S]*?)\s*```/i) || value.match(/\{[\s\S]*\}/);
  if (match) {
    try { return JSON.parse(match[1] || match[0]); } catch {}
  }
  return null;
}

function validateTaskOutput(value) {
  const parsed = tryParseJSON(value);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, reason: 'A saída da tarefa não possui JSON estruturado válido.' };
  }
  const keys = Object.keys(parsed);
  if (!keys.length) return { ok: false, reason: 'A saída estruturada está vazia.' };
  return { ok: true, data: parsed };
}

function providerFromBaseUrl() {
  try { return new URL(AI_BASE_URL).hostname; } catch { return null; }
}

async function persistAIUsage(client, organizationId, missionId, taskId, agent, response) {
  if (!response) return;
  await client.query(`INSERT INTO ai_usages
    (organization_id, mission_id, task_id, agent, provider, model, input_units, output_units, duration_ms, mode)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [
      organizationId, missionId, taskId, agent, response.provider || providerFromBaseUrl(), response.model || AI_MODEL || null,
      Number(response.usage?.prompt_tokens || response.usage?.input_tokens || 0),
      Number(response.usage?.completion_tokens || response.usage?.output_tokens || 0),
      Number(response.durationMs || 0), response.mode || AI_MODE
    ]);
}


function extractMemoryCandidates(text) {
  const candidates = [];
  if (!text) return candidates;
  const lines = String(text).split(/\n+/).map(x => x.trim()).filter(Boolean);
  for (const line of lines) {
    const m = line.match(/^(?:Público|Público-alvo|Audience)\s*:\s*(.+)$/i);
    if (m) candidates.push({ type: 'FACT', content: `Público-alvo: ${m[1]}`, importance: 75 });
    const g = line.match(/^(?:Objetivo|Goal)\s*:\s*(.+)$/i);
    if (g) candidates.push({ type: 'GOAL', content: `Objetivo: ${g[1]}`, importance: 85 });
    const d = line.match(/^(?:Decisão|Decision)\s*:\s*(.+)$/i);
    if (d) candidates.push({ type: 'DECISION', content: `Decisão: ${d[1]}`, importance: 80 });
    const p = line.match(/^(?:Preferência|Preference)\s*:\s*(.+)$/i);
    if (p) candidates.push({ type: 'PREFERENCE', content: `Preferência: ${p[1]}`, importance: 65 });
    const c = line.match(/^(?:Restrição|Constraint)\s*:\s*(.+)$/i);
    if (c) candidates.push({ type: 'CONSTRAINT', content: `Restrição: ${c[1]}`, importance: 70 });
  }
  return candidates;
}

async function writeMemories(client, organizationId, projectId, missionId, resultText) {
  const candidates = extractMemoryCandidates(resultText);
  for (const item of candidates.slice(0, 12)) {
    const exists = await client.query(`SELECT id FROM memories WHERE organization_id=$1 AND project_id=$2 AND active=true AND type=$3 AND lower(content)=lower($4) LIMIT 1`, [organizationId, projectId, item.type, item.content]);
    if (!exists.rowCount) {
      await client.query(`INSERT INTO memories (organization_id,project_id,mission_id,type,content,importance) VALUES ($1,$2,$3,$4,$5,$6)`, [organizationId, projectId, missionId, item.type, item.content, item.importance]);
    }
  }
}

async function retrieveMemories(client, organizationId, projectId, objective, limit = 8) {
  const terms = String(objective || '').toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(w => w.length >= 4).slice(0, 12);
  if (!terms.length) {
    const { rows } = await client.query(`SELECT type,content,importance,created_at FROM memories WHERE organization_id=$1 AND project_id=$2 AND active=true ORDER BY importance DESC, created_at DESC LIMIT $3`, [organizationId, projectId, limit]);
    return rows;
  }
  const conditions = terms.map((_, i) => `lower(content) LIKE $${i + 3}`).join(' OR ');
  const params = [organizationId, projectId, ...terms.map(t => `%${t}%`), limit];
  const { rows } = await client.query(`SELECT type,content,importance,created_at FROM memories WHERE organization_id=$1 AND project_id=$2 AND active=true AND (${conditions}) ORDER BY importance DESC, created_at DESC LIMIT $${terms.length + 3}`, params);
  if (rows.length) return rows;
  const fallback = await client.query(`SELECT type,content,importance,created_at FROM memories WHERE organization_id=$1 AND project_id=$2 AND active=true ORDER BY importance DESC, created_at DESC LIMIT $3`, [organizationId, projectId, limit]);
  return fallback.rows;
}

function formatMemoryContext(memories) {
  if (!memories?.length) return 'Nenhuma memória relevante registrada.';
  return memories.map(m => `- [${m.type}] ${m.content}`).join('\n');
}


function safeJson(value) {
  try { return JSON.stringify(value); } catch { return JSON.stringify({ error: 'unserializable' }); }
}

function evaluateCalculator(expression) {
  const expr = String(expression || '').trim();
  if (!expr || expr.length > 120) throw new Error('Expressão inválida.');
  if (!/^[0-9+\-*/().,%\s]+$/.test(expr)) throw new Error('Calculadora aceita apenas números e operadores básicos.');
  const normalized = expr.replace(/%/g, '/100');
  // Deliberadamente sem eval: parser simples por tokenização.
  const tokens = normalized.match(/\d+(?:\.\d+)?|[()+\-*/]/g);
  if (!tokens || tokens.join('') !== normalized.replace(/\s+/g, '')) throw new Error('Expressão inválida.');
  const values=[]; const ops=[];
  const prec={'+':1,'-':1,'*':2,'/':2};
  const apply=()=>{ const op=ops.pop(); const b=values.pop(); const a=values.pop(); if(op==='/'&&b===0) throw new Error('Divisão por zero.'); values.push(op==='+'?a+b:op==='-'?a-b:op==='*'?a*b:a/b); };
  for(let i=0;i<tokens.length;i++){
    const t=tokens[i];
    if(/^\d/.test(t)){ values.push(Number(t)); continue; }
    if(t==='('){ ops.push(t); continue; }
    if(t===')'){ while(ops.length&&ops.at  if (BILLING_MODE === 'DEMO') throw new Error('Produção exige BILLING_MODE diferente de DEMO.');
  if (!PUBLIC_ORIGIN || !PUBLIC_ORIGIN.startsWith('https://')) throw new Error('Produção exige PUBLIC_ORIGIN HTTPS.');
  if (!OWNER_EMAIL || OWNER_EMAIL.endsWith('@example.com')) throw new Error('Produção exige OWNER_EMAIL real.');
}

const pool = new Pool({ connectionString: DATABASE_URL });

function securityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    ...(NODE_ENV === 'production' ? { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } : {})
  };
}

function json(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...securityHeaders(),
    ...extraHeaders
  });
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  const declared = Number(req.headers['content-length'] || 0);
  if (declared > MAX_BODY_BYTES) throw new Error('Payload excede o limite permitido.');
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) throw new Error('Payload excede o limite permitido.');
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { throw new Error('JSON inválido.'); }
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  const { hash } = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(expectedHash, 'hex'));
}

function newToken() {
  return crypto.randomBytes(32).toString('hex');
}

function sessionCookie(token, maxAgeSeconds) {
  const secure = NODE_ENV === 'production' ? '; Secure' : '';
  return `nexus_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure}`;
}

function clearSessionCookie() {
  const secure = NODE_ENV === 'production' ? '; Secure' : '';
  return `nexus_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}

function parseCookie(header = '') {
  const out = {};
  for (const item of header.split(';')) {
    const idx = item.indexOf('=');
    if (idx > 0) out[item.slice(0, idx).trim()] = decodeURIComponent(item.slice(idx + 1).trim());
  }
  return out;
}

async function getAuth(req) {
  const token = parseCookie(req.headers.cookie || '').nexus_session;
  if (!token) return null;
  const { rows } = await pool.query(`
    SELECT s.user_id, s.expires_at, u.name, u.email, u.status,
           o.id AS organization_id, o.name AS organization_name, m.role
    FROM auth_sessions s
    JOIN users u ON u.id = s.user_id
    JOIN memberships m ON m.user_id = u.id AND m.status = 'ACTIVE'
    JOIN organizations o ON o.id = m.organization_id AND o.status = 'ACTIVE'
    WHERE s.token_hash = encode(digest($1, 'sha256'), 'hex')
      AND s.expires_at > now()
    LIMIT 1`, [token]);
  if (!rows[0]) return null;
  return {
    userId: rows[0].user_id,
    name: rows[0].name,
    email: rows[0].email,
    organizationId: rows[0].organization_id,
    organizationName: rows[0].organization_name,
    role: rows[0].role
  };
}

function requireAuth(auth, res) {
  if (!auth) { json(res, 401, { error: 'Autenticação necessária.' }); return false; }
  return true;
}

function requireOwner(auth, res) {
  if (!requireAuth(auth, res)) return false;
  if (!OWNER_EMAIL || String(auth.email).toLowerCase() !== OWNER_EMAIL) {
    json(res, 403, { error: 'Acesso restrito ao proprietário da plataforma.' });
    return false;
  }
  return true;
}

function slugify(value) {
  return value.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '').slice(0, 48) || 'workspace';
}

async function uniqueSlug(base) {
  const baseSlug = slugify(base);
  let candidate = baseSlug;
  for (let i = 1; i < 100; i++) {
    const { rowCount } = await pool.query('SELECT 1 FROM organizations WHERE slug=$1 LIMIT 1', [candidate]);
    if (!rowCount) return candidate;
    candidate = `${baseSlug}-${i + 1}`;
  }
  return `${baseSlug}-${Date.now()}`;
}


function billingPlans() {
  return [
    { code: 'FREE', name: 'Free', price: 0, interval: 'month', credits: 50, features: ['basic_workspace','basic_agents'] },
    { code: 'STARTER', name: 'Starter', price: 29.90, interval: 'month', credits: 500, features: ['standard_agents','more_missions'] },
    { code: 'PRO', name: 'Pro', price: 79.90, interval: 'month', credits: 2000, features: ['advanced_agents','larger_context','advanced_missions'] },
    { code: 'BUSINESS', name: 'Business', price: 199.90, interval: 'month', credits: 7000, features: ['team','shared_projects','analytics'] }
  ];
}

function findPlan(code) { return billingPlans().find(p => p.code === String(code || '').toUpperCase()) || null; }

async function ensureBillingSeed(client) {
  for (const plan of billingPlans()) {
    await client.query(`INSERT INTO plans (code,name,price,currency,interval,credits,features,active) VALUES ($1,$2,$3,$4,$5,$6,$7,true) ON CONFLICT (code) DO UPDATE SET name=EXCLUDED.name, price=EXCLUDED.price, currency=EXCLUDED.currency, interval=EXCLUDED.interval, credits=EXCLUDED.credits, features=EXCLUDED.features, active=true`, [plan.code, plan.name, plan.price, CURRENCY, plan.interval, plan.credits, JSON.stringify(plan.features)]);
  }
}

async function getSubscriptionState(client, organizationId) {
  const { rows } = await client.query(`SELECT s.id,s.plan_id,s.status,s.current_period_start,s.current_period_end,p.code,p.name,p.price,p.currency,p.interval,p.credits,p.features FROM subscriptions s JOIN plans p ON p.id=s.plan_id WHERE s.organization_id=$1 ORDER BY s.created_at DESC LIMIT 1`, [organizationId]);
  return rows[0] || null;
}

async function getCreditBalance(client, organizationId) {
  const { rows } = await client.query(`SELECT COALESCE(SUM(amount),0)::numeric AS balance FROM credit_ledger WHERE organization_id=$1`, [organizationId]);
  return Number(rows[0]?.balance || 0);
}

async function createDemoCheckout(client, organizationId, userId, planCode) {
  const plan = findPlan(planCode);
  if (!plan || plan.code === 'FREE') throw new Error('Plano pago inválido para checkout.');
  await ensureBillingSeed(client);
  const checkoutId = crypto.randomUUID();
  await client.query(`INSERT INTO checkout_sessions (id,organization_id,user_id,plan_id,status,provider,created_at) VALUES ($1,$2,$3,(SELECT id FROM plans WHERE code=$4),'OPEN','DEMO',now())`, [checkoutId, organizationId, userId, plan.code]);
  return { checkoutId, provider: 'DEMO', status: 'OPEN', plan };
}

async function activateDemoSubscription(client, organizationId, userId, checkoutId) {
  const checkout = (await client.query(`SELECT c.*,p.code,p.name,p.price,p.currency,p.interval,p.credits,p.features FROM checkout_sessions c JOIN plans p ON p.id=c.plan_id WHERE c.id=$1 AND c.organization_id=$2 FOR UPDATE`, [checkoutId, organizationId])).rows[0];
  if (!checkout) throw new Error('Checkout não encontrado.');
  if (checkout.status === 'COMPLETED') return checkout;
  const existing = await client.query(`SELECT id FROM subscriptions WHERE organization_id=$1 AND status='ACTIVE' LIMIT 1`, [organizationId]);
  const start = new Date();
  const end = new Date(start); end.setMonth(end.getMonth()+1);
  let subscriptionId;
  if (existing.rowCount) {
    subscriptionId = existing.rows[0].id;
    await client.query(`UPDATE subscriptions SET plan_id=$1,status='ACTIVE',current_period_start=$2,current_period_end=$3,updated_at=now() WHERE id=$4`, [checkout.plan_id,start,end,subscriptionId]);
  } else {
    subscriptionId = (await client.query(`INSERT INTO subscriptions (organization_id,plan_id,status,current_period_start,current_period_end,created_at,updated_at) VALUES ($1,$2,'ACTIVE',$3,$4,now(),now()) RETURNING id`, [organizationId,checkout.plan_id,start,end])).rows[0].id;
  }
  const payment = (await client.query(`INSERT INTO payments (organization_id,subscription_id,amount,currency,status,provider,payment_reference,created_at,paid_at) VALUES ($1,$2,$3,$4,'PAID','DEMO',$5,now(),now()) RETURNING id`, [organizationId,subscriptionId,checkout.price,checkout.currency,`demo_payment_${crypto.randomUUID()}`])).rows[0];
  const grantKey = `subscription:${subscriptionId}:${start.toISOString().slice(0,10)}`;
  await client.query(`INSERT INTO credit_ledger (organization_id,type,amount,reference,balance_after,created_at) SELECT $1,'GRANT',$2,$3,COALESCE((SELECT SUM(amount) FROM credit_ledger WHERE organization_id=$1),0)+$2,now() WHERE NOT EXISTS (SELECT 1 FROM credit_ledger WHERE organization_id=$1 AND reference=$3)`, [organizationId,checkout.credits,grantKey]);
  await client.query(`UPDATE checkout_sessions SET status='COMPLETED',completed_at=now(),updated_at=now() WHERE id=$1`, [checkoutId]);
  return { subscriptionId, paymentId: payment.id, plan: { code: checkout.code, name: checkout.name, credits: checkout.credits } };
}

async function enforceMissionCredits(client, organizationId) {
  const balance = await getCreditBalance(client, organizationId);
  const required = 25;
  if (balance < required) return { allowed: false, balance, required };
  return { allowed: true, balance, required };
}

function classify(objective) {
  const text = objective.toLowerCase();
  const complexWords = ['estratégia', 'plano', 'lançamento', 'campanha', 'aumentar vendas', 'crescer', 'marketing', 'negócio'];
  const needsResearch = ['concorrentes', 'mercado', 'tendências', 'pesquisa', 'pesquisar'].some(w => text.includes(w));
  const complex = complexWords.some(w => text.includes(w)) || text.length > 90;
  return { type: complex ? 'COMPLEX_MISSION' : 'SIMPLE', domain: needsResearch ? 'RESEARCH' : 'GENERAL', requiresResearch: needsResearch };
}

function makePlan(objective, classification) {
  const lower = objective.toLowerCase();
  const tasks = [{ title: 'Entender objetivo e contexto', agent: 'GENERAL' }];
  if (classification.requiresResearch) tasks.push({ title: 'Pesquisar informações relevantes', agent: 'RESEARCH' });
  tasks.push(lower.match(/conteúdo|instagram|tiktok|post|vídeo/) ? { title: 'Criar estratégia e conteúdo', agent: 'CONTENT' } : { title: 'Construir estratégia e ações', agent: 'STRATEGY' });
  if (lower.match(/vendas|vender|marketing|campanha|lançamento/)) tasks.push({ title: 'Transformar estratégia em ações de marketing', agent: 'MARKETING' });
  tasks.push({ title: 'Definir métricas e próximos passos', agent: 'ANALYTICS' });
  tasks.push({ title: 'Consolidar entrega final', agent: 'GENERAL' });
  return tasks;
}

async function callAI(prompt, meta = {}) {
  const started = Date.now();
  if (AI_MODE !== 'LIVE') {
    return { content: null, usage: {}, mode: 'DEMO', provider: null, model: null, durationMs: Date.now() - started };
  }
  if (!AI_BASE_URL || !AI_API_KEY || !AI_MODEL) throw new Error('IA em modo LIVE, mas AI_BASE_URL, AI_API_KEY ou AI_MODEL não está configurado.');
  const url = `${AI_BASE_URL.replace(/\/$/, '')}/chat/completions`;
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${AI_API_KEY}` },
    body: JSON.stringify({ model: AI_MODEL, messages: [
      { role: 'system', content: 'Você é o NEXUS ONE. Transforme objetivos em trabalho executável. Seja objetivo, prático e estruturado. Não invente fatos.' },
      { role: 'user', content: prompt }
    ], temperature: 0.2 })
  });
  if (!r.ok) throw new Error(`Falha no provedor de IA (${r.status}).`);
  const data = await r.json();
  const content = data?.choices?.[0]?.message?.content;
  if (!content) throw new Error('O provedor de IA não retornou conteúdo.');
  const usage = data?.usage || {};
  return {
    content,
    usage,
    mode: 'LIVE',
    provider: new URL(AI_BASE_URL).hostname,
    model: AI_MODEL,
    durationMs: Date.now() - started,
    taskId: meta.taskId,
    agent: meta.agent
  };
}

function tryParseJSON(value) {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value); } catch {}
  const match = value.match(/```json\s*([\s\S]*?)\s*```/i) || value.match(/\{[\s\S]*\}/);
  if (match) {
    try { return JSON.parse(match[1] || match[0]); } catch {}
  }
  return null;
}

function validateTaskOutput(value) {
  const parsed = tryParseJSON(value);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, reason: 'A saída da tarefa não possui JSON estruturado válido.' };
  }
  const keys = Object.keys(parsed);
  if (!keys.length) return { ok: false, reason: 'A saída estruturada está vazia.' };
  return { ok: true, data: parsed };
}

function providerFromBaseUrl() {
  try { return new URL(AI_BASE_URL).hostname; } catch { return null; }
}

async function persistAIUsage(client, organizationId, missionId, taskId, agent, response) {
  if (!response) return;
  await client.query(`INSERT INTO ai_usages
    (organization_id, mission_id, task_id, agent, provider, model, input_units, output_units, duration_ms, mode)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [
      organizationId, missionId, taskId, agent, response.provider || providerFromBaseUrl(), response.model || AI_MODEL || null,
      Number(response.usage?.prompt_tokens || response.usage?.input_tokens || 0),
      Number(response.usage?.completion_tokens || response.usage?.output_tokens || 0),
      Number(response.durationMs || 0), response.mode || AI_MODE
    ]);
}


function extractMemoryCandidates(text) {
  const candidates = [];
  if (!text) return candidates;
  const lines = String(text).split(/\n+/).map(x => x.trim()).filter(Boolean);
  for (const line of lines) {
    const m = line.match(/^(?:Público|Público-alvo|Audience)\s*:\s*(.+)$/i);
    if (m) candidates.push({ type: 'FACT', content: `Público-alvo: ${m[1]}`, importance: 75 });
    const g = line.match(/^(?:Objetivo|Goal)\s*:\s*(.+)$/i);
    if (g) candidates.push({ type: 'GOAL', content: `Objetivo: ${g[1]}`, importance: 85 });
    const d = line.match(/^(?:Decisão|Decision)\s*:\s*(.+)$/i);
    if (d) candidates.push({ type: 'DECISION', content: `Decisão: ${d[1]}`, importance: 80 });
    const p = line.match(/^(?:Preferência|Preference)\s*:\s*(.+)$/i);
    if (p) candidates.push({ type: 'PREFERENCE', content: `Preferência: ${p[1]}`, importance: 65 });
    const c = line.match(/^(?:Restrição|Constraint)\s*:\s*(.+)$/i);
    if (c) candidates.push({ type: 'CONSTRAINT', content: `Restrição: ${c[1]}`, importance: 70 });
  }
  return candidates;
}

async function writeMemories(client, organizationId, projectId, missionId, resultText) {
  const candidates = extractMemoryCandidates(resultText);
  for (const item of candidates.slice(0, 12)) {
    const exists = await client.query(`SELECT id FROM memories WHERE organization_id=$1 AND project_id=$2 AND active=true AND type=$3 AND lower(content)=lower($4) LIMIT 1`, [organizationId, projectId, item.type, item.content]);
    if (!exists.rowCount) {
      await client.query(`INSERT INTO memories (organization_id,project_id,mission_id,type,content,importance) VALUES ($1,$2,$3,$4,$5,$6)`, [organizationId, projectId, missionId, item.type, item.content, item.importance]);
    }
  }
}

async function retrieveMemories(client, organizationId, projectId, objective, limit = 8) {
  const terms = String(objective || '').toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(w => w.length >= 4).slice(0, 12);
  if (!terms.length) {
    const { rows } = await client.query(`SELECT type,content,importance,created_at FROM memories WHERE organization_id=$1 AND project_id=$2 AND active=true ORDER BY importance DESC, created_at DESC LIMIT $3`, [organizationId, projectId, limit]);
    return rows;
  }
  const conditions = terms.map((_, i) => `lower(content) LIKE $${i + 3}`).join(' OR ');
  const params = [organizationId, projectId, ...terms.map(t => `%${t}%`), limit];
  const { rows } = await client.query(`SELECT type,content,importance,created_at FROM memories WHERE organization_id=$1 AND project_id=$2 AND active=true AND (${conditions}) ORDER BY importance DESC, created_at DESC LIMIT $${terms.length + 3}`, params);
  if (rows.length) return rows;
  const fallback = await client.query(`SELECT type,content,importance,created_at FROM memories WHERE organization_id=$1 AND project_id=$2 AND active=true ORDER BY importance DESC, created_at DESC LIMIT $3`, [organizationId, projectId, limit]);
  return fallback.rows;
}

function formatMemoryContext(memories) {
  if (!memories?.length) return 'Nenhuma memória relevante registrada.';
  return memories.map(m => `- [${m.type}] ${m.content}`).join('\n');
}


function safeJson(value) {
  try { return JSON.stringify(value); } catch { return JSON.stringify({ error: 'unserializable' }); }
}

function evaluateCalculator(expression) {
  const expr = String(expression || '').trim();
  if (!expr || expr.length > 120) throw new Error('Expressão inválida.');
  if (!/^[0-9+\-*/().,%\s]+$/.test(expr)) throw new Error('Calculadora aceita apenas números e operadores básicos.');
  const normalized = expr.replace(/%/g, '/100');
  // Deliberadamente sem eval: parser simples por tokenização.
  const tokens = normalized.match(/\d+(?:\.\d+)?|[()+\-*/]/g);
  if (!tokens || tokens.join('') !== normalized.replace(/\s+/g, '')) throw new Error('Expressão inválida.');
  const values=[]; const ops=[];
  const prec={'+':1,'-':1,'*':2,'/':2};
  const apply=()=>{ const op=ops.pop(); const b=values.pop(); const a=values.pop(); if(op==='/'&&b===0) throw new Error('Divisão por zero.'); values.push(op==='+'?a+b:op==='-'?a-b:op==='*'?a*b:a/b); };
  for(let i=0;i<tokens.length;i++){
    const t=tokens[i];
    if(/^\d/.test(t)){ values.push(Number(t)); continue; }
    if(t==='('){ ops.push(t); continue; }
    if(t===')'){ while(ops.length&&ops.at
