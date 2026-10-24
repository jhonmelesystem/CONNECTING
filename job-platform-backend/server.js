const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./database');
require('dotenv').config();

const app = express();

app.use(express.json({ limit: '10mb' }));
app.use(cors());

// Servir archivos estáticos desde la carpeta 'public'
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'connecting_secreto_super_seguro';

// Ruta principal para servir la interfaz web
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: '🚀 Servidor API de CONNECTING activo y funcionando.' });
});

function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(403).json({ error: 'Token requerido' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Token inválido' });
    req.user = decoded;
    next();
  });
}

// FUNCION DE MATCHING FLEXIBLE (Smart Screening)
function checkSkillMatch(candidateSkills, requirementSkill) {
  if (!requirementSkill) return 100;
  
  const reqClean = requirementSkill.toLowerCase().trim();
  const reqItems = reqClean.split(',').map(item => item.trim()).filter(Boolean);

  let matchedItems = 0;
  const normalize = str => str.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();

  reqItems.forEach(reqSingle => {
    const reqNorm = normalize(reqSingle);

    const isMatched = candidateSkills.some(candSkill => {
      const candNorm = normalize(candSkill.skill_name);
      return candNorm.includes(reqNorm) || reqNorm.includes(candNorm) ||
             (reqNorm.includes('bachiller') && candNorm.includes('bachiller')) ||
             (reqNorm.includes('informatica') && candNorm.includes('informatica')) ||
             (reqNorm.includes('marketing') && candNorm.includes('marketing'));
    });

    if (isMatched) matchedItems++;
  });

  const totalReqs = reqItems.length > 0 ? reqItems.length : 1;
  return Math.round((matchedItems / totalReqs) * 100);
}

// ==================== AUTH & PERFIL ====================

app.post('/api/register', async (req, res) => {
  const { name, email, password, role, location, profile_picture } = req.body;
  if (!name || !email || !password || !role) {
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 8);
    const [result] = await db.query(
      `INSERT INTO users (name, email, password, role, location, profile_picture) VALUES (?, ?, ?, ?, ?, ?)`,
      [name, email, hashedPassword, role, location || '', profile_picture || '']
    );
    res.json({ message: 'Usuario registrado con éxito', userId: result.insertId });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'El correo electrónico ya está registrado' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await db.query(`SELECT * FROM users WHERE email = ?`, [email]);
    if (rows.length === 0) return res.status(400).json({ error: 'Credenciales inválidas' });

    const user = rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(400).json({ error: 'Credenciales inválidas' });

    const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({
      message: 'Login exitoso',
      token,
      role: user.role,
      userId: user.id,
      name: user.name,
      location: user.location,
      profile_picture: user.profile_picture
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/profile', verifyToken, async (req, res) => {
  const { name, location, profile_picture } = req.body;
  try {
    await db.query(
      `UPDATE users SET name = COALESCE(?, name), location = COALESCE(?, location), profile_picture = COALESCE(?, profile_picture) WHERE id = ?`,
      [name, location, profile_picture, req.user.id]
    );

    const [updatedUser] = await db.query(`SELECT id, name, role, email, location, profile_picture FROM users WHERE id = ?`, [req.user.id]);
    res.json({ message: 'Perfil actualizado correctamente', user: updatedUser[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== HABILIDADES ====================

app.post('/api/skills', verifyToken, async (req, res) => {
  if (req.user.role !== 'candidate') return res.status(403).json({ error: 'Solo candidatos' });
  const { skill_name, experience_years } = req.body;

  try {
    const [result] = await db.query(
      `INSERT INTO user_skills (user_id, skill_name, level) VALUES (?, ?, ?)`,
      [req.user.id, skill_name, experience_years || 1]
    );
    res.json({ message: 'Habilidad agregada', skillId: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/skills', verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query(`SELECT * FROM user_skills WHERE user_id = ?`, [req.user.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/skills/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'candidate') return res.status(403).json({ error: 'Solo candidatos' });
  try {
    await db.query(`DELETE FROM user_skills WHERE id = ? AND user_id = ?`, [req.params.id, req.user.id]);
    res.json({ message: 'Habilidad eliminada correctamente' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== VACANTES & APLICACIONES ====================

app.get('/api/jobs', async (req, res) => {
  try {
    const { search, modality } = req.query;
    let query = `SELECT j.*, u.name as employer_name, u.profile_picture as employer_logo, u.location as employer_location FROM jobs j JOIN users u ON j.employer_id = u.id WHERE 1=1`;
    let queryParams = [];

    if (search) {
      query += ` AND (j.title LIKE ? OR j.description LIKE ? OR j.location LIKE ?)`;
      queryParams.push(`%${search}%`, `%${search}\%`, `\%${search}%`);
    }

    if (modality && modality !== 'all') {
      query += ` AND j.modality = ?`;
      queryParams.push(modality);
    }

    query += ` ORDER BY j.created_at DESC`;

    const [jobs] = await db.query(query, queryParams);
    res.json(jobs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/employer/jobs', verifyToken, async (req, res) => {
  if (req.user.role !== 'employer') return res.status(403).json({ error: 'Acceso denegado' });
  try {
    const [jobs] = await db.query(`SELECT * FROM jobs WHERE employer_id = ? ORDER BY created_at DESC`, [req.user.id]);
    res.json(jobs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/employer/jobs/:id/applications', verifyToken, async (req, res) => {
  if (req.user.role !== 'employer') return res.status(403).json({ error: 'Acceso denegado' });
  const jobId = req.params.id;

  try {
    const [check] = await db.query(`SELECT id FROM jobs WHERE id = ? AND employer_id = ?`, [jobId, req.user.id]);
    if (check.length === 0) return res.status(404).json({ error: 'Vacante no encontrada o sin permisos' });

    const [applicants] = await db.query(`
      SELECT a.id as application_id, a.applied_at, u.id as candidate_id, u.name, u.email, u.location, u.profile_picture
      FROM applications a
      JOIN users u ON a.candidate_id = u.id
      WHERE a.job_id = ?`, [jobId]);
    res.json(applicants);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
