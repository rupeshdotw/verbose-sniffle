// db.js
import mysql from 'mysql2/promise';

const pool = mysql.createPool({
  host: 'sql12.freesqldatabase.com',      // or your XAMPP host
  user: 'sql12794799',           // your MySQL username
  password: 'alzqspWTT7',           // your MySQL password (default is empty for XAMPP)
  database: 'sql12794799', // your database name
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

export default pool;