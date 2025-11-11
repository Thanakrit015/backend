require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const verifyToken = require("./middleware/auth"); // ✅ นำเข้า middleware

const app = express();
app.use(express.json());

// 🔹 ตั้งค่าการเชื่อมต่อฐานข้อมูล
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

const SECRET_KEY = process.env.JWT_SECRET;
const PUBLIC_USER_COLUMNS =
  "id, firstname, fullname, lastname, username, status";

function maskPassword() {
  return "********";
}

// ===================== ROUTES =====================

// 🔹 ตรวจสอบเซิร์ฟเวอร์
app.get("/ping", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT NOW() AS now");
    res.json({ status: "ok", time: rows[0].now });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// 🔹 สมัครผู้ใช้ใหม่
app.post("/users", async (req, res) => {
  const { firstname, fullname, lastname, username, password, status } =
    req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.query(
      "INSERT INTO tbl_users (firstname, fullname, lastname, username, password, status) VALUES (?, ?, ?, ?, ?, ?)",
      [firstname, fullname, lastname, username, hashedPassword, status]
    );

    const [rows] = await db.query(
      `SELECT ${PUBLIC_USER_COLUMNS} FROM tbl_users WHERE id = ?`,
      [result.insertId]
    );

    const newUser = { ...rows[0], password: maskPassword() };
    res.status(201).json(newUser);
  } catch (err) {
    console.error("❌ Insert failed:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// 🔹 เข้าสู่ระบบ (Login)
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await db.query("SELECT * FROM tbl_users WHERE username = ?", [
      username,
    ]);
    if (rows.length === 0)
      return res.status(401).json({ error: "User not found" });

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign(
      { id: user.id, fullname: user.fullname, username: user.username },
      SECRET_KEY,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        fullname: user.fullname,
        username: user.username,
        status: user.status,
      },
    });
  } catch (err) {
    console.error("❌ Login failed:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// 🔹 GET /users (ต้องมี token)
app.get("/users", verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, firstname, fullname, lastname, username, status FROM tbl_users"
    );
    const masked = rows.map((u) => ({ ...u, password: maskPassword() }));
    res.json(masked);
  } catch (err) {
    res.status(500).json({ error: "Query failed" });
  }
});

// 🔹 GET /users/:id (ต้องมี token)
app.get("/users/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await db.query(
      "SELECT id, firstname, fullname, lastname, username, status FROM tbl_users WHERE id = ?",
      [id]
    );
    if (rows.length === 0)
      return res.status(404).json({ message: "User not found" });
    const user = { ...rows[0], password: maskPassword() };
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: "Query failed" });
  }
});

// 🔹 ลบผู้ใช้ (ต้องมี token)
app.delete("/users/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.query("DELETE FROM tbl_users WHERE id = ?", [id]);
    if (result.affectedRows === 0)
      return res.status(404).json({ message: "User not found" });
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error("❌ Delete failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// 🔹 เริ่มเซิร์ฟเวอร์
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`✅ Server running on http://localhost:${PORT}`)
);
