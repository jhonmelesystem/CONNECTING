const mysql = require('mysql2/promise');
require('dotenv').config();

// Railway proporciona variables de entorno automáticas cuando vinculas un servicio MySQL
const pool = mysql.createPool({
  host: process.env.MYSQLHOST || process.env.DB_HOST || 'mysql-eunn.railway.internal',
  user: process.env.MYSQLUSER || process.env.DB_USER || 'root',
  password: process.env.MYSQLPASSWORD || process.env.DB_PASSWORD || 'TzZhNbdSVrUPrzpnwVlxcUeGBwzxuakl',
  database: process.env.MYSQLDATABASE || process.env.DB_NAME || 'railway',
  port: process.env.MYSQLPORT || process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

async function initTables() {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Conectado a la base de datos MySQL.');

    // Tabla de Usuarios
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('candidate', 'employer') NOT NULL,
        location VARCHAR(255)
      ) ENGINE=InnoDB;
    `);

    // Tabla de Habilidades del Candidato
    await connection.query(`
      CREATE TABLE IF NOT EXISTS user_skills (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        skill_name VARCHAR(255) NOT NULL,
        level INT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB;
    `);

    // Tabla de Vacantes
    await connection.query(`
      CREATE TABLE IF NOT EXISTS jobs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        employer_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        location VARCHAR(255) NOT NULL,
        salary_range VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (employer_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB;
    `);

    // Tabla de Requisitos (Smart Screening)
    await connection.query(`
      CREATE TABLE IF NOT EXISTS job_requirements (
        id INT AUTO_INCREMENT PRIMARY KEY,
        job_id INT NOT NULL,
        skill_name VARCHAR(255) NOT NULL,
        level_required INT NOT NULL,
        is_mandatory BOOLEAN NOT NULL DEFAULT 1,
        FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
      ) ENGINE=InnoDB;
    `);

    // Tabla de Postulaciones
    await connection.query(`
      CREATE TABLE IF NOT EXISTS applications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        job_id INT NOT NULL,
        candidate_id INT NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_application (job_id, candidate_id),
        FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
        FOREIGN KEY (candidate_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB;
    `);

    connection.release();
    console.log('✅ Tablas inicializadas correctamente en MySQL.');
  } catch (error) {
    console.error('❌ Error al inicializar las tablas de MySQL:', error.message);
  }
}

initTables();

module.exports = pool;