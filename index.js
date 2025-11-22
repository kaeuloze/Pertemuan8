require("dotenv").config();
const mysql = require("mysql2/promise");
const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require('cors'); 

const app = express();
const PORT = process.env.PORT || 3000;

// --- KONFIGURASI ---
const KEY_PREFIX = 'APIKEY_S3CR3T_'; 
const JWT_SECRET = process.env.JWT_SECRET; 
const EXPIRY_DAYS = 30; 

app.use(express.json());
app.use(express.static('public'));
app.use(cors()); 
// ------------------------------------
// Database Connection Pool
// ------------------------------------
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD, 
    database: process.env.DB_NAME,     // Pastikan di .env isinya: api
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Middleware Verifikasi Token Admin
const authenticateAdmin = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'Akses Ditolak' });

    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.admin = verified; 
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token tidak valid' });
    }
};

// ===============================================
//           ADMIN ROUTES (CRUD)
// ===============================================

// 1. Registrasi Admin
app.post('/admin/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email & password wajib.' });
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Tabel di database: admins
        const sql = "INSERT INTO admins (EMAIL, PASSWORD) VALUES (?, ?)"; 
        await pool.query(sql, [email, hashedPassword]);

        res.status(201).json({ message: 'Admin berhasil didaftarkan.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Email sudah terdaftar.' });
        console.error("Error registrasi admin:", error);
        res.status(500).json({ error: 'Gagal mendaftarkan admin.' });
    }
});

// 2. Login Admin
app.post('/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'Data tidak lengkap.' });
        
        // Tabel di database: admins
        const sql = "SELECT ID, PASSWORD, EMAIL FROM admins WHERE EMAIL = ?";
        const [rows] = await pool.query(sql, [email]);
        
        if (rows.length === 0) return res.status(401).json({ message: 'Email/Password salah.' });

        const admin = rows[0];
        const isMatch = await bcrypt.compare(password, admin.PASSWORD);

        if (!isMatch) return res.status(401).json({ message: 'Email/Password salah.' });

        const sessionToken = jwt.sign({ id: admin.ID, email: admin.EMAIL, type: 'ADMIN_SESSION' }, JWT_SECRET, { expiresIn: '1h' });
        
        res.json({ token: sessionToken, message: 'Login berhasil' });
    } catch (error) {
        console.error("Error login:", error);
        res.status(500).json({ error: 'Server Error' });
    }
});

// 3. Admin Melihat User (PERBAIKAN DISINI)
app.get('/admin/users', authenticateAdmin, async (req, res) => {
    try {
        // PERBAIKAN: Menggunakan tabel 'user' (bukan USERS) dan 'api_keys'
        const sql = `
            SELECT 
                u.id, u.FIRST_NAME, u.LAST_NAME, u.EMAIL, 
                k.KEY_VALUE, k.START_DATE, k.OUT_OF_DATE, k.STATUS
            FROM user u
            JOIN api_keys k ON u.API_KEY_ID = k.id
        `;
        const [rows] = await pool.query(sql);
        res.json(rows);
    } catch (error) {
        console.error("Error ambil data user:", error);
        res.status(500).json({ error: 'Gagal mengambil data' });
    }
});

app.get('/', (req, res) => {
    res.json({ message: "Server API Key Manager Berjalan.", status: "OK" });
});

// ===============================================
//           USER & API KEY ROUTES
// ===============================================

// 4. Registrasi User (PERBAIKAN DISINI)
app.post('/user/register', async (req, res) => {
    const connection = await pool.getConnection();
    try {
        const { firstName, lastName, email } = req.body;
        if (!firstName || !lastName || !email) return res.status(400).json({ error: 'Data tidak lengkap.' });
        
        await connection.beginTransaction();

        // 1. Generate API Key
        const randomToken = crypto.randomBytes(16).toString('hex');
        const newApiKey = KEY_PREFIX + randomToken;
        const startDate = new Date();
        const expiryDate = new Date();
        expiryDate.setDate(startDate.getDate() + EXPIRY_DAYS); 
        const status = 'Active'; 

        // PERBAIKAN: Tabel 'api_keys'
        const sqlKey = "INSERT INTO api_keys (KEY_VALUE, START_DATE, OUT_OF_DATE, STATUS) VALUES (?, ?, ?, ?)";
        const [keyResult] = await connection.query(sqlKey, [newApiKey, startDate, expiryDate, status]);
        const apiKeyId = keyResult.insertId;

        // 2. Simpan User
        // PERBAIKAN: Tabel 'user' (bukan USERS)
        const sqlUser = "INSERT INTO user (FIRST_NAME, LAST_NAME, EMAIL, API_KEY_ID) VALUES (?, ?, ?, ?)";
        await connection.query(sqlUser, [firstName, lastName, email, apiKeyId]);
        
        await connection.commit();
        
        res.status(201).json({ 
            message: 'Registrasi berhasil',
            apiKey: newApiKey,
            expires: expiryDate.toISOString()
        });

    } catch (error) {
        await connection.rollback();
        if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Email sudah terdaftar.' });
        console.error("Error register user:", error);
        res.status(500).json({ error: 'Gagal registrasi user' });
    } finally {
        connection.release();
    }
});

// 5. Validasi API Key
app.post('/validate-apikey', async (req, res) => {
    try {
        const { apiKeyToValidate } = req.body;
        if (!apiKeyToValidate) return res.status(400).json({ error: 'API key dibutuhkan' });

        // PERBAIKAN: Tabel 'api_keys'
        const sql = "SELECT OUT_OF_DATE, STATUS FROM api_keys WHERE KEY_VALUE = ?";
        const [rows] = await pool.query(sql, [apiKeyToValidate]);

        if (rows.length === 0) return res.status(401).json({ valid: false, message: 'API Key Tidak Ditemukan' });

        const keyRecord = rows[0];
        
        // Cek Status (Pastikan logic ini sesuai, karena di screenshot data lama STATUS-nya NULL)
        // Jika ingin key lama yang NULL tetap bisa dipakai, ubah kondisi di bawah.
        if (keyRecord.STATUS !== 'Active') {
             return res.status(403).json({ valid: false, message: `API Key Tidak Aktif`, status: keyRecord.STATUS });
        }

        const expiryDate = new Date(keyRecord.OUT_OF_DATE);
        const now = new Date();

        if (now > expiryDate) {
            return res.status(403).json({ valid: false, message: 'API Key Kedaluwarsa' });
        }
        
        res.json({ valid: true, message: 'API Key Valid', expires: keyRecord.OUT_OF_DATE });

    } catch (error) {
        console.error("Error validasi:", error);
        res.status(500).json({ error: 'Gagal validasi' });
    }
});

app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});