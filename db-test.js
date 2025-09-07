require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: { require: true, rejectUnauthorized: false },
});

async function run() {
  try {
    // Verbindung testen
    const res = await pool.query('SELECT NOW() AS server_time;');
    console.log('✅ DB-Verbindung erfolgreich. Serverzeit:', res.rows[0].server_time);

    // prüfen ob users-Tabelle da ist
    const tables = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema='public' 
      ORDER BY table_name;
    `);
    console.log('📋 Tabellen:', tables.rows.map(r => r.table_name).join(', '));
  } catch (err) {
    console.error('❌ Fehler bei DB-Verbindung:', err);
  } finally {
    await pool.end();
  }
}

run();