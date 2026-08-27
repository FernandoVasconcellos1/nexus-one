import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import pg from 'pg';

const { Client } = pg;
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) throw new Error('DATABASE_URL não configurada.');

const root = path.resolve(new URL('.', import.meta.url).pathname, '..');
const dir = path.join(root, 'db', 'migrations');
const files = (await fs.readdir(dir))
  .filter(name => /^\d+_.+\.sql$/.test(name))
  .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));

const client = new Client({ connectionString: DATABASE_URL });
await client.connect();
try {
  await client.query(`CREATE TABLE IF NOT EXISTS nexus_schema_migrations (filename text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`);
  for (const file of files) {
    const exists = await client.query('SELECT 1 FROM nexus_schema_migrations WHERE filename=$1', [file]);
    if (exists.rowCount) continue;
    const sql = await fs.readFile(path.join(dir, file), 'utf8');
    await client.query('BEGIN');
    try {
      await client.query(sql);
      await client.query('INSERT INTO nexus_schema_migrations(filename) VALUES($1)', [file]);
      await client.query('COMMIT');
      console.log(`APPLIED ${file}`);
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  }
  console.log(`MIGRATIONS OK — ${files.length} migration(s) known.`);
} finally {
  await client.end();
}
