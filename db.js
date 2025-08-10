const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  throw new Error('DATABASE_URL is not defined. Please set it in your environment variables.');
}

const pool = new Pool({
  connectionString,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

pool.connect()
  .then(client => {
    console.log('Connected to the database successfully');
    client.release();
  })
  .catch(err => {
    console.error('Database connection error:', err);
    process.exit(1); // Exit the process if the connection fails
  });

module.exports = pool;