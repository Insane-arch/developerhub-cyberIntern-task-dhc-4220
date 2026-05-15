const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const app = express();

app.use(bodyParser.urlencoded({ extended: true }));

// In-memory vulnerable database
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INT, username TEXT, password TEXT, email TEXT)");
    // VULNERABILITY: Weak password storage (Plaintext)
    db.run("INSERT INTO users (id, username, password, email) VALUES (1, 'admin', 'admin123', 'admin@example.com')");
});

// Common CSS to inject into our pages to make them fancy
const commonCSS = `
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f0f2f5;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            color: #333;
        }
        .container {
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        h2 { color: #1a73e8; margin-top: 0; }
        input[type="text"], input[type="password"] {
            width: calc(100% - 20px);
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 5px;
            box-sizing: border-box;
        }
        button {
            background-color: #1a73e8;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            width: 100%;
            font-size: 16px;
            margin-top: 10px;
        }
        button:hover { background-color: #1557b0; }
        hr { border: 0; border-top: 1px solid #eee; margin: 25px 0; }
        .back-link { display: block; margin-top: 20px; color: #1a73e8; text-decoration: none; }
    </style>
`;

// VULNERABILITY: SQL Injection route
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    db.get(query, (err, row) => {
        if (row) {
            res.send(`
                ${commonCSS}
                <div class="container">
                    <h2>Welcome, ${row.username}!</h2>
                    <p>Your email is: <strong>${row.email}</strong></p>
                    <p style="color: green;">Authentication Successful (or bypassed!)</p>
                    <a href="/" class="back-link">← Back to Home</a>
                </div>
            `);
        } else {
            res.send(`
                ${commonCSS}
                <div class="container">
                    <h2 style="color: red;">Login Failed</h2>
                    <p>Invalid username or password.</p>
                    <a href="/" class="back-link">← Try Again</a>
                </div>
            `);
        }
    });
});

// VULNERABILITY: Cross-Site Scripting (XSS) route
app.get('/profile', (req, res) => {
    const userStatus = req.query.status || 'Active';
    res.send(`
        ${commonCSS}
        <div class="container">
            <h2>User Profile</h2>
            <p style="font-size: 18px;">Current Status: <span style="color: #1a73e8; font-weight: bold;">${userStatus}</span></p>
            <a href="/" class="back-link">← Back to Home</a>
        </div>
    `);
});

// Fancy UI Forms
app.get('/', (req, res) => {
    res.send(`
        ${commonCSS}
        <div class="container">
            <h2>System Login</h2>
            <form action="/login" method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            
            <hr>
            
            <h2>Test Profile Status</h2>
            <form action="/profile" method="GET">
                <input type="text" name="status" placeholder="Enter new status" required>
                <button type="submit" style="background-color: #34a853;">Update Status</button>
            </form>
        </div>
    `);
});

app.listen(3000, () => {
    console.log('Fancy App running on http://localhost:3000');
});
