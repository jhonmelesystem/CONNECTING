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

// 1. REGISTRO DE USUARIOS (Soporta Aplicante y Empleador)
app.post('/api/register', async (req, res) => {
    const { name, email, password, role, location } = req.body;
    const userRole = (role === 'employer') ? 'employer' : 'candidate';
    
    try {
        // Verificar si el correo ya existe
        const [existing] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'El correo electrónico ya está registrado' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        await db.query(
            'INSERT INTO users (name, email, password, role, location, telefono) VALUES (?, ?, ?, ?, ?, ?)',
            [name, email, hashedPassword, userRole, location || 'Santo Domingo, Distrito Nacional', '']
        );

        res.json({ message: '¡Registro exitoso! Ya puedes iniciar sesión.' });
    } catch (err) {
        console.error("❌ Error en registro:", err);
        res.status(500).json({ error: 'Error del servidor al registrar' });
    }
});

// 2. ACTUALIZAR PERFIL (Incluye Teléfono / WhatsApp)
app.put('/api/profile', verifyToken, async (req, res) => {
    const userId = req.id || req.user?.id;
    const { name, location, telefono, profile_picture } = req.body;

    try {
        const updateQuery = `
            UPDATE users 
            SET name = ?, location = ?, telefono = ?, profile_picture = ? 
            WHERE id = ?
        `;

        await db.query(updateQuery, [
            name || '', 
            location || '', 
            telefono || '', 
            profile_picture || '', 
            userId
        ]);

        const [userRes] = await db.query(
            'SELECT id, name, email, role, location, telefono, profile_picture FROM users WHERE id = ?', 
            [userId]
        );

        if (!userRes || userRes.length === 0) {
            return res.status(500).json({ error: 'Perfil actualizado pero no se pudo recuperar' });
        }

        res.json({ 
            message: '¡Perfil actualizado con éxito!', 
            user: userRes[0] 
        });

    } catch (err) {
        console.error("❌ Error en PUT /api/profile:", err);
        res.status(500).json({ error: 'Error del servidor al actualizar el perfil: ' + err.message });
    }
});

// 3. OBTENER POSTULACIONES CON TELÉFONO DEL CANDIDATO
app.get('/api/employer/jobs/:id/applications', verifyToken, async (req, res) => {
    const jobId = req.params.id;
    try {
        const query = `
            SELECT applications.*, users.name, users.email, users.telefono, users.profile_picture 
            FROM applications 
            JOIN users ON applications.candidate_id = users.id 
            WHERE applications.job_id = ?
        `;
        const [results] = await db.query(query, [jobId]);
        res.json(results);
    } catch (err) { 
        console.error("❌ Error al obtener aplicaciones:", err);
        res.status(500).json({ error: 'Error en la base de datos' });
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

// Actualizar perfil de usuario (Candidato o Empleador)
app.put('/api/profile', verifyToken, async (req, res) => {
    const userId = req.id || req.user?.id; // Asegúrate de cómo guardas el ID en tu middleware verifyToken
    const { name, location, telefono, profile_picture } = req.body;

    try {
        const updateQuery = `
            UPDATE users 
            SET name = ?, location = ?, telefono = ?, profile_picture = ? 
            WHERE id = ?
        `;

        // Usamos await en lugar de callback para mantener el estándar de tu servidor
        await db.query(updateQuery, [
            name, 
            location, 
            telefono || '', 
            profile_picture || '', 
            userId
        ]);

        // Consultamos el usuario actualizado para devolverlo
        const [userRes] = await db.query(
            'SELECT id, name, email, role, location, telefono, profile_picture FROM users WHERE id = ?', 
            [userId]
        );

        if (!userRes || userRes.length === 0) {
            return res.status(500).json({ error: 'Perfil actualizado pero no se pudo recuperar' });
        }

        res.json({ 
            message: 'Perfil actualizado con éxito', 
            user: userRes[0] 
        });

    } catch (err) {
        console.error("❌ Error en PUT /api/profile:", err);
        res.status(500).json({ error: 'Error del servidor al actualizar el perfil' });
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

// OBTENER TODAS LAS VACANTES (FEED PRINCIPAL)
app.get('/api/jobs', async (req, res) => {
  try {
    const { search, modality } = req.query;
    let query = `
      SELECT j.*, u.name as employer_name, u.profile_picture as employer_logo, u.location as employer_location 
      FROM jobs j 
      JOIN users u ON j.employer_id = u.id 
      WHERE 1=1
    `;
    let queryParams = [];

    if (search && search.trim() !== '') {
      query += ` AND (j.title LIKE ? OR j.description LIKE ? OR j.location LIKE ?)`;
      queryParams.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    if (modality && modality !== 'all') {
      query += ` AND j.modality = ?`;
      queryParams.push(modality);
    }

    query += ` ORDER BY j.created_at DESC`;

    const [jobs] = await db.query(query, queryParams);
    res.json(jobs);
  } catch (err) {
    console.error("❌ Error en GET /api/jobs:", err);
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
      WHERE a.job_id = ?
      ORDER BY a.applied_at DESC
    `, [jobId]);

    for (let candidate of applicants) {
      const [skills] = await db.query(`SELECT skill_name, level FROM user_skills WHERE user_id = ?`, [candidate.candidate_id]);
      candidate.skills = skills;
    }

    res.json(applicants);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUBLICAR NUEVA VACANTE (CORREGIDO Y ROBUSTO)
app.post('/api/jobs', verifyToken, async (req, res) => {
  if (req.user.role !== 'employer') return res.status(403).json({ error: 'Solo empleadores pueden publicar vacantes' });
  const { title, description, location, salary_range, modality, requirements } = req.body;

  if (!title || !description) {
    return res.status(400).json({ error: 'El título y la descripción son obligatorios.' });
  }

  try {
    const [result] = await db.query(
      `INSERT INTO jobs (employer_id, title, description, location, salary_range, modality) VALUES (?, ?, ?, ?, ?, ?)`,
      [req.user.id, title, description, location || '', salary_range || '', modality || 'presencial']
    );
    const jobId = result.insertId;

    if (requirements && Array.isArray(requirements) && requirements.length > 0) {
      for (let reqItem of requirements) {
        const skillName = typeof reqItem === 'string' ? reqItem : (reqItem.skill_name || 'General');
        await db.query(
          `INSERT INTO job_requirements (job_id, skill_name, level_required, is_mandatory) VALUES (?, ?, ?, 1)`,
          [jobId, skillName, 1]
        );
      }
    }

    res.json({ message: 'Vacante publicada con éxito en el feed', jobId });
  } catch (err) {
    console.error("❌ Error al publicar vacante:", err);
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/jobs/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'employer') return res.status(403).json({ error: 'Solo empleadores' });
  const jobId = req.params.id;
  const { title, description, location, salary_range, modality, requirements } = req.body;

  try {
    const [result] = await db.query(
      `UPDATE jobs SET title = ?, description = ?, location = ?, salary_range = ?, modality = ? WHERE id = ? AND employer_id = ?`,
      [title, description, location, salary_range, modality, jobId, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Vacante no encontrada o sin permisos.' });
    }

    if (requirements && Array.isArray(requirements)) {
      await db.query(`DELETE FROM job_requirements WHERE job_id = ?`, [jobId]);
      for (let reqItem of requirements) {
        const skillName = typeof reqItem === 'string' ? reqItem : (reqItem.skill_name || 'General');
        await db.query(
          `INSERT INTO job_requirements (job_id, skill_name, level_required, is_mandatory) VALUES (?, ?, ?, 1)`,
          [jobId, skillName, 1]
        );
      }
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

// OBTENER DETALLE DE VACANTE Y SMART SCREENING
// Obtener candidatos postulados a una vacante (para el empleador)
app.get('/api/employer/jobs/:id/applications', verifyToken, async (req, res) => {
    const jobId = req.params.id;
    try {
        const query = `
            SELECT applications.*, users.name, users.email, users.telefono, users.profile_picture 
            FROM applications 
            JOIN users ON applications.candidate_id = users.id 
            WHERE applications.job_id = ?
        `;
        
        // Dependiendo de tu conexión (ej. db.query con mysql2 / mysql)
        db.query(query, [jobId], async (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Error en la base de datos' });
            }

            // Para cada candidato, podemos buscar también sus habilidades si las muestras
            res.json(results);
        });
    } catch (err) { 
        console.error(err);
        res.status(500).json({ error: 'Error del servidor' });
    }
  });

app.get('/api/jobs/:id', verifyToken, async (req, res) => {
  const jobId = parseInt(req.params.id, 10);
  const candidateId = req.user.role === 'candidate' ? req.user.id : null;

  if (isNaN(jobId)) {
    return res.status(400).json({ error: 'ID de vacante inválido' });
  }


  try {
    const [jobs] = await db.query(
      `SELECT j.*, u.name as employer_name, u.profile_picture as employer_logo 
       FROM jobs j 
       LEFT JOIN users u ON j.employer_id = u.id 
       WHERE j.id = ?`,
      [jobId]
    );

    if (!jobs || jobs.length === 0) {
      return res.status(404).json({ error: 'Vacante no encontrada' });
    }

    const job = jobs[0];
    let requirements = [];
    try {
      const [reqRows] = await db.query(`SELECT * FROM job_requirements WHERE job_id = ?`, [jobId]);
      requirements = reqRows || [];
    } catch (reqErr) {
      console.warn("Advertencia al consultar job_requirements:", reqErr.message);
    }

    let eligibility = { canApply: false, matchPercentage: 0 };

    if (candidateId) {
      let candidateSkills = [];
      try {
        const [skillsRows] = await db.query(`SELECT * FROM user_skills WHERE user_id = ?`, [candidateId]);
        candidateSkills = skillsRows || [];
      } catch (skillErr) {
        console.warn("Advertencia al consultar user_skills:", skillErr.message);
      }

      if (requirements.length > 0) {
        let totalScore = 0;
        requirements.forEach(reqItem => {
          totalScore += checkSkillMatch(candidateSkills, reqItem.skill_name);
        });

        const matchPercentage = Math.min(100, Math.round(totalScore / requirements.length));
        const canApply = matchPercentage >= 85;

        eligibility = { canApply, matchPercentage };
      } else {
        eligibility = { canApply: true, matchPercentage: 100 };
      }
    }

    res.json({ job, requirements, eligibility });
  } catch (err) {
    console.error("❌ Error en GET /api/jobs/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/jobs/:id/apply', verifyToken, async (req, res) => {
  if (req.user.role !== 'candidate') return res.status(403).json({ error: 'Solo candidatos' });
  const jobId = parseInt(req.params.id, 10);
  const candidateId = req.user.id;

  if (isNaN(jobId)) {
    return res.status(400).json({ error: 'ID de vacante inválido' });
  }

  try {
    const [requirements] = await db.query(`SELECT * FROM job_requirements WHERE job_id = ?`, [jobId]);
    const [candidateSkills] = await db.query(`SELECT * FROM user_skills WHERE user_id = ?`, [candidateId]);

    if (requirements.length > 0) {
      let totalScore = 0;
      requirements.forEach(reqItem => {
        totalScore += checkSkillMatch(candidateSkills, reqItem.skill_name);
      });
      const matchPercentage = Math.min(100, Math.round(totalScore / requirements.length));

      if (matchPercentage < 85) {
        return res.status(400).json({ error: 'No alcanzas el 85% de compatibilidad requerido para esta vacante.' });
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

// ESCUCHA DEL PUERTO
const PORT = process.env.PORT || 4000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor CONNECTING corriendo correctamente en el puerto ${PORT}`);
});