const mysql = require('mysql2');

// Konfigurasi koneksi ke MySQL
const db = mysql.createConnection({
  host: 'localhost',   // server MySQL
  user: 'root',        // ganti sesuai user MySQL-mu
  password: 'mariskacan10',        // isi password MySQL jika ada
  database: 'apikeys_167' // nama database yang sudah dibuat
});

// Cek koneksi
db.connect(err => {
  if (err) {
    console.error('Gagal terhubung ke MySQL:', err);
    return;
  }
  console.log('Connected to MySQL database.');
});

// Export db agar bisa digunakan di index.js
module.exports = db;
