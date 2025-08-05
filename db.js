const { Pool } = require('pg');

console.log('DATABASE_URL:', process.env.DATABASE_URL); // Debug line

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

module.exports = pool;