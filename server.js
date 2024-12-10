const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const http = require("http");
const { Server } = require("socket.io");
const { body, param, query, validationResult } = require("express-validator");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(bodyParser.json());

// JWT Secret - use environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key_please_use_env';

// Database connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "service_platform",
});

db.connect((err) => {
  if (err) throw err;
  console.log("Connected to database");
});

// Authentication Middleware
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Create Tables
db.query(`
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(15),
    password VARCHAR(255) NOT NULL,
    role ENUM('user', 'provider') DEFAULT 'user'
  )
`, (err) => {
  if (err) throw err;
});

db.query(`
  CREATE TABLE IF NOT EXISTS service_provider_details (
    id INT PRIMARY KEY,
    photo VARCHAR(255),
    profession VARCHAR(255),
    experience INT,
    specific_skills TEXT,
    description TEXT,
    qualities TEXT,
    service_area VARCHAR(255),
    availability TEXT,
    rating FLOAT DEFAULT 0,
    certification VARCHAR(255),
    estimated_pricing TEXT,
    FOREIGN KEY (id) REFERENCES users(id)
  )
`, (err) => {
  if (err) throw err;
});

db.query(`
  CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    content TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_read BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
  )
`, (err) => {
  if (err) throw err;
});

// Authentication Routes
// Registration Route
app.post('/auth/register', [
  body('name').isString().notEmpty().withMessage('Name is required'),
  body('email').isEmail().withMessage('Invalid email format'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('phone').optional().isMobilePhone().withMessage('Invalid phone number')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, email, password, phone, role = 'user' } = req.body;

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    
    if (results.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) return res.status(500).json({ error: err.message });

      const sql = 'INSERT INTO users (name, email, phone, password, role) VALUES (?, ?, ?, ?, ?)';
      db.query(sql, [name, email, phone, hashedPassword, role], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });

        const token = jwt.sign(
          { id: result.insertId, email, role }, 
          JWT_SECRET, 
          { expiresIn: '24h' }
        );

        res.status(201).json({ 
          message: 'User registered successfully', 
          userId: result.insertId,
          token 
        });
      });
    });
  });
});

// Login Route
app.post('/auth/login', [
  body('email').isEmail().withMessage('Invalid email format'),
  body('password').notEmpty().withMessage('Password is required')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    
    if (results.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      if (!result) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role }, 
        JWT_SECRET, 
        { expiresIn: '24h' }
      );

      res.json({ 
        message: 'Login successful', 
        userId: user.id,
        token 
      });
    });
  });
});

// Validation Middleware
const validateProvider = [
  body("name").isString().notEmpty(),
    body("email").isEmail(),
    body("password").isLength({ min: 6 }),
    body("phone").isMobilePhone(),
    body("details.profession").optional().isString(),
    body("details.experience").optional().isInt(),
    body("details.specific_skills").optional().isString(),
    body("details.description").optional().isString(),
    body("details.qualities").optional().isString(),
    body("details.service_area").optional().isString(),
    body("details.availability").optional().isString(),
    body("details.certification").optional().isString(),
    body("details.estimated_pricing").optional().isString()
];

const validateId = [
  param("id").isInt().withMessage("ID must be an integer"),
];

// Error Handling Middleware
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Provider Endpoints (with authentication)
app.post("/providers", 
  authMiddleware, 
  validateProvider,
  handleValidationErrors,
  (req, res) => {
    const { name, email, password, phone, details = {} } = req.body;

    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) return res.status(500).json({ error: err.message });

      const userSql = 'INSERT INTO users (name, email, phone, password, role) VALUES (?, ?, ?, ?, "provider")';
      db.query(userSql, [name, email, phone, hashedPassword], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });

        const providerSql = `
          INSERT INTO service_provider_details (
            id, photo, profession, experience, specific_skills, 
            description, qualities, service_area, availability, 
            rating, certification, estimated_pricing
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        db.query(
          providerSql, 
          [
            result.insertId, 
            details.photo || null,
            details.profession || null,
            details.experience || null,
            details.specific_skills || null,
            details.description || null,
            details.qualities || null,
            details.service_area || null,
            details.availability || null,
            details.rating || 0,
            details.certification || null,
            details.estimated_pricing || null
          ], 
          (err) => {
            if (err) return res.status(500).json({ error: err.message });
            
            const token = jwt.sign(
              { id: result.insertId, email, role: 'provider' }, 
              JWT_SECRET, 
              { expiresIn: '24h' }
            );

            res.status(201).json({ 
              message: "Provider added successfully", 
              userId: result.insertId,
              token 
            });
          }
        );
      });
    });
  }
);

// Socket.IO connection
io.on("connection", (socket) => {
  console.log("A user connected:", socket.id);

  socket.on("sendMessage", (data) => {
    const { sender_id, receiver_id, content } = data;

    const sql = 'INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)';
    db.query(sql, [sender_id, receiver_id, content], (err, result) => {
      if (err) {
        console.error(err.message);
        socket.emit("error", { message: "Message could not be sent" });
        return;
      }

      io.to(receiver_id).emit("newMessage", {
        id: result.insertId,
        sender_id,
        receiver_id,
        content,
        timestamp: new Date(),
      });

      socket.emit("messageSent", { message: "Message sent successfully" });
    });
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

// Messaging Endpoints
app.post("/messages", authMiddleware, (req, res) => {
  const { receiver_id, content } = req.body;
  const sender_id = req.user.id;

  const sql = 'INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)';
  db.query(sql, [sender_id, receiver_id, content], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });

    io.to(receiver_id).emit("newMessage", {
      id: result.insertId,
      sender_id,
      receiver_id,
      content,
      timestamp: new Date(),
    });

    res.json({ message: "Message sent successfully" });
  });
});

app.get("/messages/conversation/:userId", authMiddleware, (req, res) => {
  const { userId } = req.params;
  const authenticatedUserId = req.user.id;

  const sql = `
    SELECT * FROM messages 
    WHERE (sender_id = ? AND receiver_id = ?) 
       OR (sender_id = ? AND receiver_id = ?)
    ORDER BY timestamp ASC
  `;
  db.query(
    sql,
    [authenticatedUserId, userId, userId, authenticatedUserId],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    }
  );
});

app.get("/messages/unread", authMiddleware, (req, res) => {
  const authenticatedUserId = req.user.id;
  
  console.log("Authenticated User ID:", authenticatedUserId);
  
  const sql = `SELECT * FROM messages WHERE receiver_id = ? AND is_read = FALSE`;
  db.query(sql, [authenticatedUserId], (err, results) => {
      if (err) {
          console.error("Database Error:", err);
          return res.status(500).json({ error: err.message });
      }
      
      console.log("Unread Messages Query Results:", results);
      console.log("Number of Unread Messages:", results.length);
      
      res.json(results);
  });
});

app.put("/messages/:id/mark-as-read", authMiddleware, (req, res) => {
  const { id } = req.params;

  const sql = 'UPDATE messages SET is_read = TRUE WHERE id = ?';
  db.query(sql, [id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: "Message marked as read" });
  });
});



app.get("/providers/search", authMiddleware, [
  // Optional query parameter validations
  query('name').optional().trim(),
  query('profession').optional().trim(),
  query('service_area').optional().trim(),
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 50 }).toInt()
], handleValidationErrors, (req, res) => {
  const { name, profession, service_area, page = 1, limit = 10 } = req.query;
  
  // dynamic SQL query
  let sql = `
    SELECT 
      u.id, 
      u.name, 
      u.email, 
      u.phone, 
      spd.profession, 
      spd.experience, 
      spd.specific_skills, 
      spd.description, 
      spd.service_area, 
      spd.rating,
      spd.estimated_pricing
    FROM users u
    JOIN service_provider_details spd ON u.id = spd.id
    WHERE u.role = 'provider'
  `;

  // Array to hold dynamic query parameters
  const params = [];

  // dynamic WHERE conditions
  const conditions = [];

  if (name) {
    conditions.push("u.name LIKE ?");
    params.push(`%${name}%`);
  }

  if (profession) {
    conditions.push("spd.profession LIKE ?");
    params.push(`%${profession}%`);
  }

  if (service_area) {
    conditions.push("spd.service_area LIKE ?");
    params.push(`%${service_area}%`);
  }

  // conditions to SQL if any exist
  if (conditions.length > 0) {
    sql += " AND " + conditions.join(" AND ");
  }

  // pagination
  const offset = (page - 1) * limit;
  sql += " LIMIT ? OFFSET ?";
  params.push(limit, offset);

  // Count total matching providers for pagination
  const countSql = `
    SELECT COUNT(*) as total 
    FROM users u
    JOIN service_provider_details spd ON u.id = spd.id
    WHERE u.role = 'provider'
    ${conditions.length > 0 ? "AND " + conditions.join(" AND ") : ""}
  `;

  // Execute count query
  db.query(countSql, params.slice(0, conditions.length), (countErr, countResults) => {
    if (countErr) {
      return res.status(500).json({ error: countErr.message });
    }

    const totalProviders = countResults[0].total;
    const totalPages = Math.ceil(totalProviders / limit);

    // Execute main query
    db.query(sql, params, (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      res.json({
        providers: results,
        pagination: {
          currentPage: page,
          totalPages,
          totalProviders,
          pageSize: limit
        }
      });
    });
  });
});


// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});