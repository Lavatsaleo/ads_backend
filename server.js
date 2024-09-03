const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const PasswordValidator = require('password-validator');

// Load environment variables from .env file
dotenv.config();

const app = express();
const SECRET_KEY = process.env.SECRET_KEY;

// Enable CORS with specific origin and credentials
app.use(cors({
    origin: 'http://localhost:3001', // Replace with your React app's origin
    credentials: true
}));

// Middleware to parse JSON bodies and cookies
app.use(express.json());
app.use(cookieParser());

// Create a connection to the MySQL database using environment variables
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// Connect to the database
db.connect((err) => {
    if (err) {
        console.error('Error connecting to the database:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

// Create a schema for password validation
const passwordSchema = new PasswordValidator();
passwordSchema
    .is().min(8)                                    // Minimum length 8
    .is().max(100)                                  // Maximum length 100
    .has().uppercase()                              // Must have uppercase letters
    .has().lowercase()                              // Must have lowercase letters
    .has().digits(2)                                // Must have at least 2 digits
    .has().not().spaces()                           // Should not have spaces
    .is().not().oneOf(['Passw0rd', 'Password123']); // Blacklist common passwords

// Middleware to check if the user is an admin
function isAdmin(req, res, next) {
    const accessToken = req.cookies.accessToken;
    if (!accessToken) {
        return res.status(403).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(accessToken, SECRET_KEY);
        const findUserQuery = 'SELECT * FROM users WHERE id = ?';
        db.query(findUserQuery, [decoded.id], (err, results) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (results.length === 0) return res.status(401).json({ message: 'User not found' });

            const user = results[0];
            if (user.role === 'admin') {
                req.user = user; // Attach the user to the request object
                next(); // User is admin, proceed to the next middleware/route handler
            } else {
                res.status(403).json({ message: 'Access denied' });
            }
        });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
}

// User registration route
app.post('/register', (req, res) => {
    const { username, password, role } = req.body;

    console.log('Received registration data:', req.body); // Log the request body

    // Validate the password against the schema
    const passwordValidationResult = passwordSchema.validate(password, { details: true });
    if (passwordValidationResult.length > 0) {
        return res.status(400).json({ 
            message: 'Password does not meet the required criteria', 
            details: passwordValidationResult 
        });
    }

    // Check if the username already exists
    const checkUserQuery = 'SELECT * FROM users WHERE username = ?';
    db.query(checkUserQuery, [username], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (results.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash the password
        const hashedPassword = bcrypt.hashSync(password, 10);

        // Insert the new user into the database with the role
        const insertUserQuery = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
        db.query(insertUserQuery, [username, hashedPassword, role || 'viewer'], (err, results) => {
            if (err) return res.status(500).json({ error: 'Database error' });

            res.json({ message: 'User registered successfully' });
        });
    });
});

// Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Check if the user exists
    const findUserQuery = 'SELECT * FROM users WHERE username = ?';
    db.query(findUserQuery, [username], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const user = results[0];
        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate JWT token
        const accessToken = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
        const refreshToken = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '7d' });

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict'
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict'
        });

        res.json({ message: 'Logged in successfully' });
    });
});

// Refresh token route
app.post('/token', (req, res) => {
    const refreshToken = req.cookies.refreshToken; // Retrieve refresh token from cookies
    if (!refreshToken) {
        return res.status(403).json({ message: 'Refresh token is required' });
    }

    try {
        const user = jwt.verify(refreshToken, SECRET_KEY);
        const newAccessToken = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
        res.cookie('accessToken', newAccessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict'
        });
        res.json({ message: 'Token refreshed successfully' });
    } catch (error) {
        res.status(403).json({ message: 'Invalid refresh token' });
    }
});

// Logout route
app.post('/logout', (req, res) => {
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.json({ message: 'Logged out successfully' });
});

// Protected route (e.g., dashboard)
app.get('/dashboard', (req, res) => {
    const accessToken = req.cookies.accessToken; // Retrieve token from cookies
    if (!accessToken) {
        return res.status(403).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(accessToken, SECRET_KEY);
        const findUserQuery = 'SELECT * FROM users WHERE id = ?';
        db.query(findUserQuery, [decoded.id], (err, results) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (results.length === 0) return res.status(401).json({ message: 'User not found' });

            const user = results[0];
            if (user.role === 'uploader') {
                res.json({ message: `Welcome, ${user.username}`, data: 'Dashboard data with upload access' });
            } else if (user.role === 'viewer') {
                res.json({ message: `Welcome, ${user.username}`, data: 'Dashboard data view only' });
            } else {
                res.status(403).json({ message: 'Access denied' });
            }
        });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

// Admin route to add new users
app.post('/admin/add-user', isAdmin, (req, res) => {
    const { username, password, role } = req.body;

    const passwordValidationResult = passwordSchema.validate(password, { details: true });
    if (passwordValidationResult.length > 0) {
        return res.status(400).json({ 
            message: 'Password does not meet the required criteria', 
            details: passwordValidationResult 
        });
    }

    const checkUserQuery = 'SELECT * FROM users WHERE username = ?';
    db.query(checkUserQuery, [username], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (results.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        const insertUserQuery = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
        db.query(insertUserQuery, [username, hashedPassword, role || 'viewer'], (err, results) => {
            if (err) return res.status(500).json({ error: 'Database error' });

            res.json({ message: 'User added successfully' });
        });
    });
});

// Admin route to upload CSV files
app.post('/admin/upload-csv', isAdmin, (req, res) => {
    // Implement CSV upload functionality
    res.json({ message: 'CSV upload functionality to be implemented' });
});

// Start the server
app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});
