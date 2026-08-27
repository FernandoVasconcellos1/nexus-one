import fs from 'node:fs';
import process from 'node:process';

const required = [
  ['NODE_ENV', 'development|production'],
  ['DATABASE_URL', 'postgres connection string'],
  ['PUBLIC_ORIGIN', 'http(s) origin'],
  ['AI_MODE', 'DEMO or LIVE'],
  ['BILLING_MODE', 'DEMO or LIVE'],
];

const errors = [];
const warnings = [];
const env = process.env;

for (const [name] of required) {
  if (!String(env[name] || '').trim()) errors.push(`${name} is missing`);
}

if (!['development', 'test', 'production'].includes(env.NODE_ENV || '')) {
  errors.push('NODE_ENV must be development, test, or production');
}

if (!/^https?:\/\//.test(env.PUBLIC_ORIGIN || '')) {
  errors.push('PUBLIC_ORIGIN must start with http:// or https://');
}

if (String(env.NODE_ENV).toLowerCase() === 'production') {
  const checks = [
    ['AI_MODE', 'LIVE'],
    ['BILLING_MODE', 'LIVE'],
  ];
  for (const [name, expected] of checks) {
    if (String(env[name] || '').toUpperCase() !== expected) errors.push(`Production requires ${name}=${expected}`);
  }
  if (!String(env.PUBLIC_ORIGIN).startsWith('https://')) errors.push('Production requires HTTPS PUBLIC_ORIGIN');
  if (!env.OWNER_EMAIL || /@example\.com$/i.test(env.OWNER_EMAIL)) errors.push('Production requires a real OWNER_EMAIL');
  if (!env.AUTH_SECRET || env.AUTH_SECRET.length < 32) warnings.push('AUTH_SECRET should be configured with a high-entropy value (32+ chars).');
  if (!env.AI_API_KEY) errors.push('Production requires AI_API_KEY');
  if (!env.AI_BASE_URL) errors.push('Production requires AI_BASE_URL');
  if (!env.AI_MODEL) errors.push('Production requires AI_MODEL');
  if (!env.PAYMENT_PROVIDER) errors.push('Production requires PAYMENT_PROVIDER');
  if (!env.PAYMENT_WEBHOOK_SECRET) errors.push('Production requires PAYMENT_WEBHOOK_SECRET');
}

console.log('NEXUS ONE PRE-FLIGHT');
console.log(`Environment: ${env.NODE_ENV || '(missing)'}`);
console.log(`AI mode: ${env.AI_MODE || '(missing)'}`);
console.log(`Billing mode: ${env.BILLING_MODE || '(missing)'}`);

for (const warning of warnings) console.warn(`WARN: ${warning}`);
for (const error of errors) console.error(`ERROR: ${error}`);

if (errors.length) {
  console.error(`\nPRE-FLIGHT FAILED — ${errors.length} blocking issue(s).`);
  process.exit(1);
}

console.log('\nPRE-FLIGHT PASSED.');
