// db.js
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
});

const logger = require('./utils/logger');

// 🛡️ Veritabanı Sağlığı: Beklenmeyen hataları yakala
pool.on('error', (err) => {
  logger.error('🚨 Kritik DB Hatası (idle client):', { message: err.message, stack: err.stack });
  // Process manager (PM2, systemd vb.) uygulamayı yeniden başlatacak
  process.exit(-1);
});

module.exports = pool;