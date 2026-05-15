/**
 * @file server.js
 * @description Enterprise-Grade Secure User Management System
 * @author Muhammad Hamza Naseer
 * @module Developershub_Internship_Task
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const winston = require('winston');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || 'super_secret_internship_key_v2';

// ==========================================
// 1. ADVANCED LOGGING CONFIGURATION (WINSTON)
// ==========================================
const customFormat = winston.format.printf(({ level, message, timestamp }) => {
    return `[${timestamp}] [${level.toUpperCase()}]: ${message}`;
});

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(winston.format.timestamp(), customFormat),
    transports: [
        new winston.transports.File({ filename: 'security-audit.log', level: 'warn' }),
        new winston.transports.Console({
            format: winston.format.combine(winston.format.colorize(), customFormat)
        })
    ]
});

// ==========================================
// 2. ENTERPRISE SECURITY MIDDLEWARE
// ==========================================

// Parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Enable CORS for expected origins
app.use(cors({ origin: 'http://localhost:3000' }));

// Advanced Helmet Config (Strict Content Security Policy)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"], // Blocks inline scripts (Stops XSS)
            styleSrc: ["'self'", "'unsafe-inline'"],
            upgradeInsecureRequests: [],
        },
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// Brute-Force Protection (Limits login attempts)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login requests per window
    message: "Too many login attempts from this IP, please try again after 15 minutes.",
    handler: (req, res, next, options) => {
        logger.warn(`BRUTE FORCE ATTEMPT DETECTED: IP ${req.ip} exceeded rate limit.`);
        res.status(options.statusCode).send(options.message);
    }
});

// ==========================================
// 3. DATABASE INITIALIZATION
// ==========================================
const db = new sqlite3.Database(':memory:');

const initDB = async () => {
    db.serialize(async () => {
        db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, email TEXT)");
        
        try {
            const saltRounds = 12; // Increased complexity
            const hashedPassword = await bcrypt.hash('admin123', saltRounds);
            const stmt = db.prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
            stmt.run('admin', hashedPassword, 'admin@developershub.com');
            stmt.finalize();
            logger.info('Database securely initialized and seeded.');
        } catch (error) {
            logger.error(`Database seeding failed: ${error.message}`);
        }
    });
};
initDB();

// ==========================================
// 4. SECURE ROUTES
// ==========================================

// Root Route (Frontend)
app.get('/', (req, res) => {
    res.send(`
        <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px;">
            <h2>Secure System Login</h2>
            <form action="/api/v1/auth/login" method="POST" style="margin-bottom: 20px;">
                <input type="text" name="username" placeholder="Username" required style="display:block; margin-bottom:10px; padding:8px; width:100%;">
                <input type="password" name="password" placeholder="Password" required style="display:block; margin-bottom:10px; padding:8px; width:100%;">
                <button type="submit" style="padding:10px 15px; background:#007BFF; color:white; border:none; border-radius:4px;">Secure Login</button>
            </form>
            <hr>
            <h2>Update Profile Status</h2>
            <form action="/api/v1/profile" method="GET">
                <input type="text" name="status" placeholder="Enter status..." required style="display:block; margin-bottom:10px; padding:8px; width:100%;">
                <button type="submit" style="padding:10px 15px; background:#28A745; color:white; border:none; border-radius:4px;">Update Status</button>
            </form>
        </div>
    `);
});

// Secure Authentication Endpoint
app.post('/api/v1/auth/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send("Bad Request: Missing credentials.");
    }

    const query = "SELECT * FROM users WHERE username = ?";
    
    db.get(query, [username], async (err, user) => {
        if (err) {
            logger.error(`DB_ERROR during authentication: ${err.message}`);
            return res.status(500).send("Internal Server Error");
        }

        if (!user) {
            logger.warn(`AUTH_FAIL: Invalid username attempted -> '${validator.escape(username)}'`);
            return res.status(401).send("Invalid credentials!");
        }

        try {
            const passwordMatch = await bcrypt.compare(password, user.password);
            
            if (passwordMatch) {
                const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '2h' });
                logger.info(`AUTH_SUCCESS: User '${username}' authenticated successfully.`);
                res.status(200).send(`
                    <h3 style="color: green;">Authentication Successful</h3>
                    <p>Welcome, ${validator.escape(user.username)}!</p>
                    <div style="background:#eee; padding:10px; word-wrap:break-word;">
                        <strong>Issued JWT:</strong><br>${token}
                    </div>
                `);
            } else {
                logger.warn(`AUTH_FAIL: Invalid password for user -> '${username}'`);
                res.status(401).send("Invalid credentials!");
            }
        } catch (bcryptError) {
            logger.error(`BCRYPT_ERROR: ${bcryptError.message}`);
            res.status(500).send("Internal Server Error");
        }
    });
});

// Secure Profile Endpoint (Sanitized)
app.get('/api/v1/profile', (req, res) => {
    const rawStatus = req.query.status || 'Active';
    
    // Strict input sanitization
    const safeStatus = validator.escape(rawStatus);

    res.send(`
        <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px;">
            <h3>User Profile</h3>
            <p>Current Status: <span style="background: #e3f2fd; padding: 5px; border-radius: 4px;">${safeStatus}</span></p>
            <a href="/" style="text-decoration:none; color:#007BFF;">&larr; Return to Dashboard</a>
        </div>
    `);
});

// ==========================================
// 5. SERVER INITIALIZATION
// ==========================================
app.listen(PORT, () => {
    logger.info(`Enterprise Security Server active on port ${PORT}`);
    logger.info(`Helmet Security Headers: ENABLED`);
    logger.info(`Rate Limiting: ENABLED (Max 5 req/15min)`);
});
