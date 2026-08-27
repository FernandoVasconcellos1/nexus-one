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
    if(t===')'){ while(ops.length&&ops.at(-1)!=='(') apply(); if(ops.pop()!=='(') throw new Error('Parênteses inválidos.'); continue; }
    if('+-*/'.includes(t)){
      if(t==='-'&&(i===0||['(','+','-','*','/'].includes(tokens[i-1]))){ values.push(0); }
      while(ops.length&&ops.at(-1)!=='('&&prec[ops.at(-1)]>=prec[t]) apply(); ops.push(t);
    }
  }
  while(ops.length) { if(ops.at(-1)==='(') throw new Error('Parênteses inválidos.'); apply(); }
  if(values.length!==1||!Number.isFinite(values[0])) throw new Error('Expressão inválida.');
  return values[0];
}

async function executeTool(client, ctx, tool, input) {
  const started = Date.now();
  let status='COMPLETED'; let output; let error=null;
  try {
    if (tool === 'calculator') {
      output = { result: evaluateCalculator(input?.expression) };
    } else if (tool === 'web_search') {
      if (!WEB_SEARCH_URL) throw new Error('WEB_SEARCH_URL não configurada.');
      const url = new URL(WEB_SEARCH_URL);
      url.searchParams.set('q', String(input?.query || ''));
      const r = await fetch(url, { headers: WEB_SEARCH_API_KEY ? { authorization: `Bearer ${WEB_SEARCH_API_KEY}` } : {} });
      if (!r.ok) throw new Error(`Falha na ferramenta de pesquisa (${r.status}).`);
      const data = await r.json();
      output = data;
    } else {
      throw new Error(`Ferramenta não suportada: ${tool}`);
    }
  } catch (e) {
    status='FAILED'; error=e.message;
  }
  const row = (await client.query(`INSERT INTO tool_calls
    (organization_id, mission_id, task_id, tool, input, output, status, duration_ms, error)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, [
      ctx.organizationId, ctx.missionId, ctx.taskId, tool, safeJson(input||{}), output==null?null:safeJson(output), status, Date.now()-started, error
  ])).rows[0];
  if (status==='FAILED') throw new Error(error || 'Falha na ferramenta.');
  return { id: row.id, data: output, durationMs: Date.now()-started };
}

function toolForTask(planned) {
  const text = `${planned.title || ''} ${planned.description || ''}`.toLowerCase();
  if (planned.agent === 'RESEARCH' || /pesquis|concorr|mercado|tendên/.test(text)) return 'web_search';
  return null;
}

async function runMission(missionId, organizationId, workerClient) {

  const missionRes = await workerClient.query(`
    SELECT m.id, m.organization_id AS "organizationId", m.project_id AS "projectId", m.objective, m.plan,
           p.name AS "projectName"
    FROM missions m
    JOIN projects p ON p.id = m.project_id AND p.organization_id = m.organization_id
    WHERE m.id=$1 AND m.organization_id=$2
    FOR UPDATE`, [missionId, organizationId]);
  const mission = missionRes.rows[0];
  if (!mission) throw new Error('Missão não encontrada.');

  await workerClient.query('UPDATE missions SET status=$1, started_at=COALESCE(started_at, now()), updated_at=now() WHERE id=$2 AND organization_id=$3', ['RUNNING', missionId, organizationId]);
  const plannedTasks = Array.isArray(mission.plan) ? mission.plan : [];
  const relevantMemories = await retrieveMemories(workerClient, organizationId, mission.projectId, mission.objective);
  const memoryContext = formatMemoryContext(relevantMemories);
  const outputs = [];

  for (const planned of plannedTasks) {
    const task = (await workerClient.query(`
      INSERT INTO tasks (organization_id, mission_id, title, agent, status)
      VALUES ($1,$2,$3,$4,'RUNNING') RETURNING *`,
      [organizationId, missionId, planned.title, planned.agent])).rows[0];

    let output = null;
    let taskError = null;

    for (let attempt = 1; attempt <= MAX_AGENT_RETRIES; attempt++) {
      try {
        let toolContext = '';
        const requiredTool = toolForTask(planned);
        if (requiredTool === 'calculator') {
          const toolResult = await executeTool(workerClient, { organizationId, missionId, taskId: task.id }, 'calculator', { expression: mission.objective });
          toolContext = `\nResultado da calculadora: ${JSON.stringify(toolResult.data)}`;
        } else if (requiredTool === 'web_search') {
          const toolResult = await executeTool(workerClient, { organizationId, missionId, taskId: task.id }, 'web_search', { query: `${mission.objective} ${planned.title}` });
          toolContext = `\nResultado da pesquisa externa: ${JSON.stringify(toolResult.data)}`;
        }
        const prompt = `Objetivo: ${mission.objective}\nTarefa: ${planned.title}\nAgente: ${planned.agent}\nContexto do projeto: ${mission.projectName || ''}\nMemórias relevantes do projeto:\n${memoryContext}${toolContext}\n\nUse as memórias e ferramentas somente quando forem pertinentes. Não invente fatos. Responda SOMENTE com JSON válido, sem markdown. O objeto deve conter chaves úteis para esta tarefa e conteúdo prático.`;
        const response = await callAI(prompt, { taskId: task.id, agent: planned.agent });
        if (AI_MODE === 'DEMO') {
          output = `Modo DEMO: etapa "${planned.title}" executada pelo agente ${planned.agent}.`;
          break;
        }
        await persistAIUsage(workerClient, organizationId, missionId, task.id, planned.agent, response);
        const validation = validateTaskOutput(response.content);
        if (!validation.ok) throw new Error(validation.reason);
        output = JSON.stringify(validation.data, null, 2);
        break;
      } catch (e) {
        taskError = e.message;
        if (attempt === MAX_AGENT_RETRIES) break;
      }
    }

    if (!output) {
      await workerClient.query(`UPDATE tasks SET error=$1, status='FAILED', updated_at=now() WHERE id=$2`, [taskError || 'Falha na execução.', task.id]);
      throw new Error(taskError || `Falha na tarefa ${planned.title}.`);
    }

    await workerClient.query(`UPDATE tasks SET output=$1, error=NULL, status='COMPLETED', updated_at=now() WHERE id=$2`, [output, task.id]);
    outputs.push({ agent: planned.agent, task: planned.title, output });
  }

  if (AI_MODE === 'LIVE') {
    let consolidated = null;
    let consolidationError = null;
    for (let attempt = 1; attempt <= MAX_AGENT_RETRIES; attempt++) {
      try {
        const response = await callAI(`Consolide os resultados abaixo em JSON válido, sem markdown. Retorne um objeto com as chaves: summary, diagnosis, strategy, actions, metrics, next_actions.\nObjetivo: ${mission.objective}\n\n${outputs.map(x => `AGENTE ${x.agent}\nTAREFA ${x.task}\n${x.output}`).join('\n\n')}`, { agent: 'GENERAL' });
        const validation = validateTaskOutput(response.content);
        if (!validation.ok) throw new Error(validation.reason);
        consolidated = JSON.stringify(validation.data, null, 2);
        await persistAIUsage(workerClient, organizationId, missionId, null, 'GENERAL', response);
        break;
      } catch (e) {
        consolidationError = e.message;
      }
    }
    if (!consolidated) throw new Error(consolidationError || 'Falha na consolidação da missão.');
    await workerClient.query('UPDATE missions SET result=$1, status=$2, completed_at=now(), updated_at=now() WHERE id=$3 AND organization_id=$4', [consolidated, 'COMPLETED', missionId, organizationId]);
    await writeMemories(workerClient, organizationId, mission.projectId, missionId, consolidated);
    return consolidated;
  }

  const demoResult = `# Resultado NEXUS ONE\n\n## Objetivo\n${mission.objective}\n\n## Plano\n${outputs.map((x, i) => `${i + 1}. ${x.task}`).join('\n')}\n\n## Próximos passos\n1. Execute a prioridade mais importante.\n2. Meça o resultado.\n3. Retorne ao NEXUS para a próxima missão.`;
  await workerClient.query('UPDATE missions SET result=$1, status=$2, completed_at=now(), updated_at=now() WHERE id=$3 AND organization_id=$4', [demoResult, 'COMPLETED', missionId, organizationId]);
  await writeMemories(workerClient, organizationId, mission.projectId, missionId, demoResult);
  return demoResult;
}

async function claimJob() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(`
      SELECT id, mission_id, organization_id, attempts, max_attempts
      FROM jobs
      WHERE status IN ('QUEUED','RETRYING')
        AND available_at <= now()
      ORDER BY created_at
      FOR UPDATE SKIP LOCKED
      LIMIT 1`);
    if (!rows[0]) { await client.query('ROLLBACK'); return null; }
    const job = rows[0];
    await client.query(`UPDATE jobs
      SET status='RUNNING', attempts=attempts+1, locked_at=now(), worker_id=$1,
          started_at=COALESCE(started_at, now()), updated_at=now()
      WHERE id=$2`, [WORKER_ID, job.id]);
    await client.query('COMMIT');
    return job;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    throw e;
  } finally {
    client.release();
  }
}

async function processJob(job) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await runMission(job.mission_id, job.organization_id, client);
    await client.query('UPDATE jobs SET status=\'COMPLETED\', completed_at=now(), updated_at=now() WHERE id=$1', [job.id]);
    await client.query('COMMIT');
    console.log(`NEXUS worker: job ${job.id} completed`);
    return result;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    const attempts = Number(job.attempts || 0);
    const status = attempts < Number(job.max_attempts || 3) ? 'RETRYING' : 'DEAD';
    const delaySeconds = Math.min(60, 2 ** Math.max(0, attempts - 1));
    await pool.query(`UPDATE jobs SET status=$1, error=$2, available_at=now() + ($3 || ' seconds')::interval, updated_at=now(), completed_at=CASE WHEN $1='DEAD' THEN now() ELSE NULL END WHERE id=$4`, [status, e.message, delaySeconds, job.id]);
    await pool.query(`UPDATE missions SET status='${status === 'DEAD' ? 'FAILED' : 'READY'}', updated_at=now() WHERE id=$1 AND organization_id=$2`, [job.mission_id, job.organization_id]);
    console.error(`NEXUS worker: job ${job.id} ${status}: ${e.message}`);
  } finally {
    client.release();
  }
}

let workerBusy = false;
async function workerLoop() {
  if (workerBusy) return;
  workerBusy = true;
  try {
    const job = await claimJob();
    if (job) await processJob(job);
  } catch (e) {
    console.error('NEXUS worker loop error:', e);
  } finally {
    workerBusy = false;
    setTimeout(workerLoop, WORKER_POLL_MS);
  }
}


function clientKey(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || req.socket.remoteAddress || 'unknown';
}

function rateLimited(req) {
  const now = Date.now();
  const key = clientKey(req);
  const bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.start >= RATE_LIMIT_WINDOW_MS) {
    rateBuckets.set(key, { start: now, count: 1 });
    return false;
  }
  bucket.count += 1;
  return bucket.count > RATE_LIMIT_MAX;
}

function validateBrowserOrigin(req) {
  if (!PUBLIC_ORIGIN) return true;
  const origin = req.headers.origin;
  if (!origin) return true;
  return origin === PUBLIC_ORIGIN;
}

function isStateChanging(req) {
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method || '');
}

async function handleAPI(req, res, url) {
  if (rateLimited(req)) { json(res, 429, { error: 'Muitas requisições. Tente novamente em instantes.' }, { 'Retry-After': '60' }); return true; }
  if (isStateChanging(req) && url.pathname !== '/api/webhooks/payment' && !validateBrowserOrigin(req)) { json(res, 403, { error: 'Origem da requisição não autorizada.' }); return true; }
  if (url.pathname === '/api/health' && req.method === 'GET') {
    try {
      await pool.query('SELECT 1');
      const q = await pool.query(`SELECT count(*) FILTER (WHERE status IN ('QUEUED','RETRYING'))::int AS queued, count(*) FILTER (WHERE status='RUNNING')::int AS running FROM jobs`);
      return json(res, 200, { ok: true, service: 'NEXUS ONE', database: 'ok', worker: { id: WORKER_ID, ...q.rows[0] } });
    } catch { return json(res, 503, { ok: false, service: 'NEXUS ONE', database: 'error' }); }
  }

  if (url.pathname === '/api/auth/signup' && req.method === 'POST') {
    const body = await readBody(req);
    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (name.length < 2 || !email.includes('@') || password.length < 8) return json(res, 400, { error: 'Nome, e-mail válido e senha com pelo menos 8 caracteres são obrigatórios.' });
    const { salt, hash } = hashPassword(password);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const exists = await client.query('SELECT 1 FROM users WHERE email=$1', [email]);
      if (exists.rowCount) { await client.query('ROLLBACK'); return json(res, 409, { error: 'E-mail já cadastrado.' }); }
      const user = (await client.query('INSERT INTO users (name,email,password_hash,password_salt) VALUES ($1,$2,$3,$4) RETURNING id,name,email', [name,email,hash,salt])).rows[0];
      const orgName = `${name}'s Workspace`;
      const slugBase = await uniqueSlug(orgName);
      const org = (await client.query('INSERT INTO organizations (name,slug) VALUES ($1,$2) RETURNING id,name,slug', [orgName,slugBase])).rows[0];
      await client.query('INSERT INTO memberships (user_id,organization_id,role) VALUES ($1,$2,\'OWNER\')', [user.id, org.id]);
      await ensureBillingSeed(client);
      const freePlan = await client.query(`SELECT id,credits FROM plans WHERE code='FREE' LIMIT 1`);
      if (freePlan.rowCount) {
        await client.query(`INSERT INTO credit_ledger (organization_id,type,amount,reference,balance_after,created_at) VALUES ($1,'GRANT',$2,$3,$2,now()) ON CONFLICT (organization_id,reference) DO NOTHING`, [org.id, Number(freePlan.rows[0].credits), 'signup-free-grant']);
      }
      const project = (await client.query('INSERT INTO projects (organization_id,name,description,created_by) VALUES ($1,$2,$3,$4) RETURNING id,name', [org.id,'Primeiro Projeto','Projeto inicial do NEXUS ONE.',user.id])).rows[0];
      const token = newToken();
      await client.query(`INSERT INTO auth_sessions (user_id, token_hash, expires_at) VALUES ($1, encode(digest($2,'sha256'),'hex'), now() + ($3 || ' days')::interval)`, [user.id, token, SESSION_TTL_DAYS]);
      await client.query('COMMIT');
      res.setHeader('Set-Cookie', sessionCookie(token, SESSION_TTL_DAYS * 86400));
      return json(res, 201, { user, organization: org, project });
    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  }

  if (url.pathname === '/api/auth/me' && req.method === 'GET') {
    const auth = await getAuth(req);
    if (!auth) return json(res, 401, { error: 'Não autenticado.' });
    return json(res, 200, { user: { id: auth.userId, name: auth.name, email: auth.email }, organization: { id: auth.organizationId, name: auth.organizationName }, role: auth.role });
  }

  if (url.pathname === '/api/auth/login' && req.method === 'POST') {
    const body = await readBody(req);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const { rows } = await pool.query('SELECT id,name,email,status,password_hash,password_salt FROM users WHERE email=$1 LIMIT 1', [email]);
    const user = rows[0];
    if (!user || user.status !== 'ACTIVE' || !verifyPassword(password, user.password_salt, user.password_hash)) return json(res, 401, { error: 'Credenciais inválidas.' });
    const token = newToken();
    await pool.query(`INSERT INTO auth_sessions (user_id, token_hash, expires_at) VALUES ($1, encode(digest($2,'sha256'),'hex'), now() + ($3 || ' days')::interval)`, [user.id, token, SESSION_TTL_DAYS]);
    res.setHeader('Set-Cookie', sessionCookie(token, SESSION_TTL_DAYS * 86400));
    return json(res, 200, { user: { id: user.id, name: user.name, email: user.email } });
  }

  if (url.pathname === '/api/auth/logout' && req.method === 'POST') {
    const token = parseCookie(req.headers.cookie || '').nexus_session;
    if (token) await pool.query('DELETE FROM auth_sessions WHERE token_hash=encode(digest($1,\'sha256\'),\'hex\')', [token]);
    res.setHeader('Set-Cookie', clearSessionCookie());
    return json(res, 200, { ok: true });
  }

  const auth = await getAuth(req);
  if (url.pathname === '/api/billing/plans' && req.method === 'GET') {
    const client = await pool.connect();
    try { await ensureBillingSeed(client); } finally { client.release(); }
    return json(res, 200, { plans: billingPlans(), currency: CURRENCY });
  }

  if (url.pathname === '/api/billing/me' && req.method === 'GET') {
    const client = await pool.connect();
    try { await ensureBillingSeed(client); const sub = await getSubscriptionState(client, auth.organizationId); const balance = await getCreditBalance(client, auth.organizationId); return json(res, 200, { subscription: sub, credit_balance: balance, billing_mode: BILLING_MODE }); } finally { client.release(); }
  }

  if (url.pathname === '/api/billing/checkout' && req.method === 'POST') {
    const body = await readBody(req);
    const planCode = String(body.plan || '').toUpperCase();
    const plan = findPlan(planCode);
    if (!plan || plan.code === 'FREE') return json(res, 400, { error: 'Selecione um plano pago válido.' });
    const client = await pool.connect();
    try { await client.query('BEGIN'); const checkout = await createDemoCheckout(client, auth.organizationId, auth.userId, plan.code); await client.query('COMMIT'); return json(res, 201, { checkout }); } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  }

  const checkoutComplete = url.pathname.match(/^\/api\/billing\/checkout\/([0-9a-f-]+)\/complete$/i);
  if (checkoutComplete && req.method === 'POST') {
    if (BILLING_MODE !== 'DEMO') return json(res, 400, { error: 'Conclusão simulada disponível apenas em BILLING_MODE=DEMO.' });
    const client = await pool.connect();
    try { await client.query('BEGIN'); const result = await activateDemoSubscription(client, auth.organizationId, auth.userId, checkoutComplete[1]); await client.query('COMMIT'); return json(res, 200, { ok: true, ...result }); } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  }

  if (url.pathname === '/api/billing/credits' && req.method === 'GET') {
    const client = await pool.connect();
    try { const balance = await getCreditBalance(client, auth.organizationId); const { rows } = await client.query(`SELECT type,amount,reference,balance_after,created_at FROM credit_ledger WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 50`, [auth.organizationId]); return json(res, 200, { balance, ledger: rows }); } finally { client.release(); }
  }

  if (!requireAuth(auth, res)) return true;

  if (url.pathname === '/api/projects' && req.method === 'GET') {
    const { rows } = await pool.query('SELECT id,name,description,objective,status,created_at,updated_at FROM projects WHERE organization_id=$1 AND status<>\'DELETED\' ORDER BY created_at DESC', [auth.organizationId]);
    return json(res, 200, { projects: rows });
  }

  if (url.pathname === '/api/projects' && req.method === 'POST') {
    const body = await readBody(req); const name = String(body.name || '').trim();
    if (name.length < 2) return json(res, 400, { error: 'Nome do projeto é obrigatório.' });
    const { rows } = await pool.query('INSERT INTO projects (organization_id,name,description,objective,created_by) VALUES ($1,$2,$3,$4,$5) RETURNING *', [auth.organizationId,name,String(body.description||''),String(body.objective||''),auth.userId]);
    return json(res, 201, { project: rows[0] });
  }

  const memoryMatch = url.pathname.match(/^\/api\/projects\/([0-9a-f-]+)\/memories$/i);
  if (memoryMatch && req.method === 'GET') {
    const projectId = memoryMatch[1];
    const { rows } = await pool.query(`SELECT id,type,content,importance,active,created_at,updated_at FROM memories WHERE organization_id=$1 AND project_id=$2 AND active=true ORDER BY importance DESC, created_at DESC LIMIT 100`, [auth.organizationId, projectId]);
    return json(res, 200, { memories: rows });
  }

  if (url.pathname === '/api/missions' && req.method === 'GET') {
    const { rows } = await pool.query('SELECT id,project_id,objective,classification,plan,result,status,created_at,updated_at,completed_at FROM missions WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 50', [auth.organizationId]);
    return json(res, 200, { missions: rows });
  }

  if (url.pathname === '/api/missions' && req.method === 'POST') {
    const body = await readBody(req);
    const objective = String(body.objective || '').trim();
    if (!objective) return json(res, 400, { error: 'Informe um objetivo.' });
    const creditClient = await pool.connect();
    try { await ensureBillingSeed(creditClient); const gate = await enforceMissionCredits(creditClient, auth.organizationId); if (!gate.allowed) return json(res, 402, { error: 'Limite de créditos atingido.', billing: { balance: gate.balance, required: gate.required, action: 'UPGRADE' } }); } finally { creditClient.release(); }
    let projectId = body.projectId;
    if (projectId) {
      const check = await pool.query('SELECT id,name FROM projects WHERE id=$1 AND organization_id=$2 AND status=\'ACTIVE\'', [projectId, auth.organizationId]);
      if (!check.rowCount) return json(res, 404, { error: 'Projeto não encontrado.' });
    } else {
      const p = await pool.query('SELECT id FROM projects WHERE organization_id=$1 AND status=\'ACTIVE\' ORDER BY created_at LIMIT 1', [auth.organizationId]);
      if (!p.rowCount) return json(res, 400, { error: 'Crie um projeto primeiro.' });
      projectId = p.rows[0].id;
    }
    const classification = classify(objective);
    const tasks = makePlan(objective, classification);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const project = await client.query("SELECT id,name FROM projects WHERE id=$1 AND organization_id=$2 AND status='ACTIVE'", [projectId, auth.organizationId]);
      if (!project.rowCount) { await client.query('ROLLBACK'); return json(res, 404, { error: 'Projeto não encontrado.' }); }
      const mission = (await client.query(`INSERT INTO missions (organization_id,project_id,created_by,objective,classification,plan,status) VALUES ($1,$2,$3,$4,$5,$6,'READY') RETURNING id,objective,classification,plan,status,created_at`, [auth.organizationId,projectId,auth.userId,objective,classification,tasks])).rows[0];
      const job = (await client.query(`INSERT INTO jobs (type,mission_id,organization_id,status) VALUES ('MISSION_EXECUTION',$1,$2,'QUEUED') RETURNING id,status,created_at`, [mission.id, auth.organizationId])).rows[0];
      await client.query('COMMIT');
      return json(res, 202, { mission: { ...mission, project_id: projectId }, job });
    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  }

  const jobMatch = url.pathname.match(/^\/api\/jobs\/([0-9a-f-]+)$/i);
  if (jobMatch && req.method === 'GET') {
    const { rows } = await pool.query('SELECT id,type,mission_id,status,attempts,max_attempts,error,created_at,started_at,completed_at FROM jobs WHERE id=$1 AND organization_id=$2 LIMIT 1', [jobMatch[1], auth.organizationId]);
    if (!rows[0]) return json(res, 404, { error: 'Job não encontrado.' });
    return json(res, 200, { job: rows[0] });
  }

  const toolCallsMatch = url.pathname.match(/^\/api\/missions\/([0-9a-f-]+)\/tools$/i);
  if (toolCallsMatch && req.method === 'GET') {
    const { rows } = await pool.query('SELECT id,task_id,tool,input,output,status,duration_ms,error,created_at FROM tool_calls WHERE mission_id=$1 AND organization_id=$2 ORDER BY created_at ASC', [toolCallsMatch[1], auth.organizationId]);
    return json(res, 200, { tool_calls: rows });
  }

  const missionMatch = url.pathname.match(/^\/api\/missions\/([0-9a-f-]+)$/i);
  if (missionMatch && req.method === 'GET') {
    const { rows } = await pool.query('SELECT * FROM missions WHERE id=$1 AND organization_id=$2 LIMIT 1', [missionMatch[1], auth.organizationId]);
    if (!rows[0]) return json(res, 404, { error: 'Missão não encontrada.' });
    const tasks = await pool.query('SELECT * FROM tasks WHERE mission_id=$1 AND organization_id=$2 ORDER BY created_at', [missionMatch[1], auth.organizationId]);
    return json(res, 200, { mission: rows[0], tasks: tasks.rows });
  }

  if (url.pathname === '/api/owner/me' && req.method === 'GET') {
    if (!requireOwner(auth, res)) return true;
    return json(res, 200, { owner: { email: auth.email, name: auth.name, role: 'PLATFORM_OWNER' } });
  }

  if (url.pathname === '/api/owner/overview' && req.method === 'GET') {
    if (!requireOwner(auth, res)) return true;
    const client = await pool.connect();
    try {
      await ensureBillingSeed(client);
      const [users, orgs, paid, mrr, missions, completed, ai, partners, commissions, payments, failedPayments] = await Promise.all([
        client.query(`SELECT COUNT(*)::int AS count FROM users WHERE status <> 'DELETED'`),
        client.query(`SELECT COUNT(*)::int AS count FROM organizations WHERE status = 'ACTIVE'`),
        client.query(`SELECT COUNT(DISTINCT organization_id)::int AS count FROM subscriptions WHERE status='ACTIVE' AND plan_id <> (SELECT id FROM plans WHERE code='FREE')`),
        client.query(`SELECT COALESCE(SUM(p.price),0)::numeric AS value FROM subscriptions s JOIN plans p ON p.id=s.plan_id WHERE s.status='ACTIVE' AND p.code <> 'FREE'`),
        client.query(`SELECT COUNT(*)::int AS count FROM missions`),
        client.query(`SELECT COUNT(*)::int AS count FROM missions WHERE status='COMPLETED'`),
        client.query(`SELECT COALESCE(SUM(estimated_cost),0)::numeric AS value, COUNT(*)::int AS count FROM ai_usages`),
        client.query(`SELECT COUNT(*)::int AS count FROM affiliate_accounts WHERE status='APPROVED'`),
        client.query(`SELECT COALESCE(SUM(amount),0)::numeric AS value FROM commissions`),
        client.query(`SELECT COALESCE(SUM(amount) FILTER (WHERE status='PAID'),0)::numeric AS value FROM payments`),
        client.query(`SELECT COUNT(*)::int AS count FROM payments WHERE status='FAILED'`)
      ]);
      const alerts = [];
      const q = Number(failedPayments.rows[0].count || 0);
      if (q > 0) alerts.push({ severity: 'MEDIUM', message: `${q} pagamento(s) falho(s) registrados.` });
      const missionTotal = Number(missions.rows[0].count || 0);
      const missionCompleted = Number(completed.rows[0].count || 0);
      if (missionTotal >= 10 && missionCompleted / missionTotal < 0.8) alerts.push({ severity: 'HIGH', message: 'Taxa de conclusão de missões abaixo de 80%.' });
      return json(res, 200, {
        generated_at: new Date().toISOString(),
        metrics: {
          users: Number(users.rows[0].count || 0),
          organizations: Number(orgs.rows[0].count || 0),
          paid_customers: Number(paid.rows[0].count || 0),
          mrr: Number(mrr.rows[0].value || 0),
          missions: missionTotal,
          completed_missions: missionCompleted,
          mission_success_rate: missionTotal ? Number((missionCompleted / missionTotal).toFixed(4)) : null,
          ai_cost: Number(ai.rows[0].value || 0),
          ai_calls: Number(ai.rows[0].count || 0),
          approved_partners: Number(partners.rows[0].count || 0),
          commissions: Number(commissions.rows[0].value || 0),
          paid_revenue: Number(payments.rows[0].value || 0),
          failed_payments: q
        },
        alerts
      });
    } finally { client.release(); }
  }

  if (url.pathname === '/api/owner/organizations' && req.method === 'GET') {
    if (!requireOwner(auth, res)) return true;
    const { rows } = await pool.query(`
      SELECT o.id,o.name,o.slug,o.status,o.created_at,
             COUNT(DISTINCT m.user_id)::int AS members,
             COUNT(DISTINCT p.id)::int AS projects,
             COUNT(DISTINCT mi.id)::int AS missions,
             COALESCE(sub.status,'NONE') AS subscription_status,
             COALESCE(pl.code,'FREE') AS plan_code
      FROM organizations o
      LEFT JOIN memberships m ON m.organization_id=o.id AND m.status='ACTIVE'
      LEFT JOIN projects p ON p.organization_id=o.id AND p.status <> 'DELETED'
      LEFT JOIN missions mi ON mi.organization_id=o.id
      LEFT JOIN LATERAL (SELECT s.status,s.plan_id FROM subscriptions s WHERE s.organization_id=o.id ORDER BY s.created_at DESC LIMIT 1) sub ON true
      LEFT JOIN plans pl ON pl.id=sub.plan_id
      GROUP BY o.id,sub.status,pl.code
      ORDER BY o.created_at DESC LIMIT 100`);
    return json(res, 200, { organizations: rows });
  }

  if (url.pathname === '/api/owner/payments' && req.method === 'GET') {
    if (!requireOwner(auth, res)) return true;
    const { rows } = await pool.query(`
      SELECT p.id,p.organization_id,p.amount,p.currency,p.status,p.provider,p.created_at,p.paid_at,o.name AS organization_name,pl.code AS plan_code
      FROM payments p
      JOIN organizations o ON o.id=p.organization_id
      LEFT JOIN subscriptions s ON s.id=p.subscription_id
      LEFT JOIN plans pl ON pl.id=s.plan_id
      ORDER BY p.created_at DESC LIMIT 100`);
    return json(res, 200, { payments: rows });
  }

  return false;
}

const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };
async function serveStatic(req, res, url) {
  const pathname = url.pathname === '/' ? '/index.html' : url.pathname;
  const filePath = path.normalize(path.join(publicDir, pathname));
  if (!filePath.startsWith(publicDir)) return json(res, 403, { error: 'Forbidden' });
  try { const data = await fs.readFile(filePath); res.writeHead(200, { 'Content-Type': mime[path.extname(filePath)] || 'application/octet-stream', ...securityHeaders() }); res.end(data); }
  catch { json(res, 404, { error: 'Not found' }); }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (url.pathname.startsWith('/api/')) {
      const handled = await handleAPI(req, res, url);
      if (handled !== false) return;
    }
    await serveStatic(req, res, url);
  } catch (err) {
    console.error(err);
    json(res, 500, { error: 'Erro interno do servidor.' });
  }
});

await pool.query('SELECT 1');
server.listen(PORT, () => {
  console.log(`NEXUS ONE: http://localhost:${PORT}`);
  workerLoop();
});

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`NEXUS ONE: shutting down (${signal})`);
  server.close(async () => {
    try { await pool.end(); } finally { process.exit(0); }
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
pool.on('error', err => console.error('NEXUS PostgreSQL pool error:', err));
