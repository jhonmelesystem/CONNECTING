const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./database');
require('dotenv').config();

const app = express();

// Middlewares
app.use(express.json({ limit: '10mb' })); // Soporte para imágenes Base64
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'connecting_secreto_super_seguro';

// Ruta de salud
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: '🚀 Servidor API de CONNECTING activo y funcionando.' });
});

// Middleware de autenticación
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

// ==================== AUTH Y PERFIL ====================

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

// ==================== VACANTES Y SMART SCREENING (85%) ====================

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

app.post('/api/jobs', verifyToken, async (req, res) => {
  if (req.user.role !== 'employer') return res.status(403).json({ error: 'Solo empleadores' });
  const { title, description, location, salary_range, modality, requirements } = req.body;

  try {
    const [result] = await db.query(
      `INSERT INTO jobs (employer_id, title, description, location, salary_range, modality) VALUES (?, ?, ?, ?, ?, ?)`,
      [req.user.id, title, description, location, salary_range, modality || 'presencial']
    );
    const jobId = result.insertId;

    if (requirements && Array.isArray(requirements)) {
      for (let reqItem of requirements) {
        await db.query(
          `INSERT INTO job_requirements (job_id, skill_name, level_required, is_mandatory) VALUES (?, ?, ?, 1)`,
          [jobId, reqItem.skill_name, reqItem.level_required || 1]
        );
      }
    }

    res.json({ message: 'Vacante creada con éxito', jobId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/jobs/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'employer') return res.status(403).json({ error: 'Solo empleadores' });
  const jobId = req.params.id;
  const { title, description, location, salary_range, modality } = req.body;

  try {
    const [result] = await db.query(
      `UPDATE jobs SET title = ?, description = ?, location = ?, salary_range = ?, modality = ? WHERE id = ? AND employer_id = ?`,
      [title, description, location, salary_range, modality, jobId, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Vacante no encontrada o sin permisos.' });
    }

    res.json({ message: 'Vacante actualizada correctamente' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/jobs/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'employer') return res.status(403).json({ error: 'Solo empleadores' });
  const jobId = req.params.id;

  try {
    await db.query(`DELETE FROM job_requirements WHERE job_id = ?`, [jobId]);
    await db.query(`DELETE FROM applications WHERE job_id = ?`, [jobId]);
    await db.query(`DELETE FROM jobs WHERE id = ? AND employer_id = ?`, [jobId, req.user.id]);
    res.json({ message: 'Vacante eliminada con éxito' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/jobs/:id', async (req, res) => {
  const jobId = req.params.id;
  
  let candidateId = null;
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      candidateId = decoded.id;
    } catch (e) {}
  }

  try {
    const [jobs] = await db.query(`SELECT j.*, u.name as employer_name FROM jobs j JOIN users u ON j.employer_id = u.id WHERE j.id = ?`, [jobId]);
    if (jobs.length === 0) return res.status(404).json({ error: 'Vacante no encontrada' });

    const job = jobs[0];
    const [requirements] = await db.query(`SELECT * FROM job_requirements WHERE job_id = ?`, [jobId]);

    let eligibility = { canApply: false, matchPercentage: 100 };

    if (candidateId) {
      const [candidateSkills] = await db.query(`SELECT * FROM user_skills WHERE user_id = ?`, [candidateId]);

      if (requirements.length > 0) {
        let matchedCount = 0;
        requirements.forEach(reqItem => {
          const found = candidateSkills.some(s => s.skill_name.toLowerCase() === reqItem.skill_name.toLowerCase());
          if (found) matchedCount++;
        });

        const matchPercentage = Math.round((matchedCount / requirements.length) * 100);
        const canApply = matchPercentage >= 85;

        eligibility = { canApply, matchPercentage };
      } else {
        eligibility = { canApply: true, matchPercentage: 100 };
      }
    }

    res.json({ job, requirements, eligibility });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/jobs/:id/apply', verifyToken, async (req, res) => {
  if (req.user.role !== 'candidate') return res.status(403).json({ error: 'Solo candidatos' });
  const jobId = req.params.id;
  const candidateId = req.user.id;

  try {
    const [requirements] = await db.query(`SELECT * FROM job_requirements WHERE job_id = ?`, [jobId]);
    const [candidateSkills] = await db.query(`SELECT * FROM user_skills WHERE user_id = ?`, [candidateId]);

    if (requirements.length > 0) {
      let matchedCount = 0;
      requirements.forEach(reqItem => {
        const found = candidateSkills.some(s => s.skill_name.toLowerCase() === reqItem.skill_name.toLowerCase());
        if (found) matchedCount++;
      });
      const matchPercentage = Math.round((matchedCount / requirements.length) * 100);

      if (matchPercentage < 85) {
        return res.status(400).json({ error: 'No alcanzas el 85% de compatibilidad requerido para postularte.' });
      }
    }

    await db.query(
      `INSERT INTO applications (job_id, candidate_id, status) VALUES (?, ?, 'pending')`,
      [jobId, candidateId]
    );

    res.json({ message: '¡Postulación realizada con éxito!' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Ya te has postulado a esta vacante.' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor CONNECTING corriendo en el puerto ${PORT}`);
});