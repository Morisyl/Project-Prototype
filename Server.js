require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const path = require('path');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(__dirname)); // Serve static files from the root directory
app.use(helmet()); // Set security headers

// MySQL database connection setup
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to database:', err);
        return;
    }
    console.log('Connected to database');

    // Create tables if they don't exist
    const createTables = () => {
        const createBookingsTable = `
            CREATE TABLE IF NOT EXISTS bookings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                gender ENUM('male', 'female') NOT NULL,
                home_phone VARCHAR(20),
                office_phone VARCHAR(20),
                service VARCHAR(255) NOT NULL,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `;
        
        const createEnquiriesTable = `
            CREATE TABLE IF NOT EXISTS enquiries (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `;

        const createUsersTable = `
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `;

        db.query(createBookingsTable, (err) => {
            if (err) {
                console.error('Error creating bookings table:', err);
            } else {
                console.log('Bookings table ready');
            }
        });
        
        db.query(createEnquiriesTable, (err) => {
            if (err) {
                console.error('Error creating enquiries table:', err);
            } else {
                console.log('Enquiries table ready');
            }
        });

        db.query(createUsersTable, (err) => {
            if (err) {
                console.error('Error creating users table:', err);
            } else {
                console.log('Users table ready');
            }
        });
    };

    // Call createTables function to ensure tables are created
    createTables();
});

// Routes
// Serve HTML files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Booking route
app.post('/booking', (req, res) => {
    const { name, email, gender, homePhone, officePhone, service, details } = req.body;
    const query = 'INSERT INTO bookings (name, email, gender, home_phone, office_phone, service, details) VALUES (?, ?, ?, ?, ?, ?, ?)';
    db.query(query, [name, email, gender, homePhone, officePhone, service, details], (err) => {
        if (err) {
            console.error('Error saving booking:', err);
            res.status(500).json({ message: 'Error saving booking' });
        } else {
            res.json({ message: 'Booking saved successfully' });
        }
    });
});

// Enquiry route
app.post('/enquiries', (req, res) => {
    const { name, email, message } = req.body;
    const query = 'INSERT INTO enquiries (name, email, message) VALUES (?, ?, ?)';
    db.query(query, [name, email, message], (err) => {
        if (err) {
            console.error('Error saving enquiry:', err);
            res.status(500).json({ message: 'Error saving enquiry' });
        } else {
            res.json({ message: 'Enquiry saved successfully' });
        }
    });
});

// Registration route
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        // Check if email already exists
        const checkQuery = 'SELECT * FROM users WHERE email = ?';
        db.query(checkQuery, [email], async (err, results) => {
            if (err) {
                console.error('Error checking existing user:', err);
                return res.status(500).json({ message: 'Error registering user' });
            }

            if (results.length > 0) {
                return res.status(400).json({ message: 'Email already registered' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
            db.query(query, [username, email, hashedPassword], (err) => {
                if (err) {
                    console.error('Error registering user:', err);
                    res.status(500).json({ message: 'Error registering user' });
                } else {
                    res.json({ message: 'Registration successful' });
                }
            });
        });
    } catch (err) {
        console.error('Error hashing password:', err);
        res.status(500).json({ message: 'Error registering user' });
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ message: 'Error logging in' });
        }

        if (results.length === 0) {
            console.log('User not found');
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const user = results[0];

        try {
            const match = await bcrypt.compare(password, user.password);

            if (match) {
                const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
                console.log('Login successful');
                return res.json({ message: 'Login successful', token });
            } else {
                console.log('Password does not match');
                return res.status(400).json({ message: 'Invalid email or password' });
            }
        } catch (err) {
            console.error('Error during password comparison:', err);
            return res.status(500).json({ message: 'Error logging in' });
        }
    });
});

// Forgot Password route
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        // Check if email exists in the database
        const query = 'SELECT * FROM users WHERE email = ?';
        db.query(query, [email], (err, results) => {
            if (err) {
                console.error('Error checking email:', err);
                return res.status(500).json({ message: 'Error processing request' });
            }

            if (results.length === 0) {
                // To prevent enumeration, send the same response
                return res.json({ message: 'Password reset link sent if email is registered' });
            }

            // Generate a password reset token
            const resetToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '15m' });

            // Create a reset link
            const resetLink = `${process.env.RESET_PASSWORD_URL}/${resetToken}`;

            // Send email with the reset link
            const transporter = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            });

            const mailOptions = {
                from: 'no-reply@example.com',
                to: email,
                subject: 'Password Reset',
                text: `You can reset your password using the following link: ${resetLink}`
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('Error sending email:', error);
                    return res.status(500).json({ message: 'Error sending password reset email' });
                } else {
                    console.log('Password reset email sent:', info.response);
                    return res.json({ message: 'Password reset link sent if email is registered' });
                }
            });
        });
    } catch (err) {
        console.error('Error in forgot-password route:', err);
        res.status(500).json({ message: 'Error processing request' });
    }
});

// Reset Password route (for demonstration purposes)
app.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;

    try {
        // Verify the token
        jwt.verify(token, process.env.JWT_SECRET, (err) => {
            if (err) {
                console.error('Invalid or expired token:', err);
                return res.status(400).json({ message: 'Invalid or expired token' });
            }

            res.sendFile(path.join(__dirname, 'reset-password.html'));
        });
    } catch (err) {
        console.error('Error verifying token:', err);
        res.status(500).json({ message: 'Error verifying token' });
    }
});

// Handle reset password POST request (for demonstration purposes)
app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    try {
        // Verify the token
        jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
            if (err) {
                console.error('Invalid or expired token:', err);
                return res.status(400).json({ message: 'Invalid or expired token' });
            }

            const hashedPassword = await bcrypt.hash(newPassword, 10);
            const query = 'UPDATE users SET password = ? WHERE email = ?';
            db.query(query, [hashedPassword, decoded.email], (err) => {
                if (err) {
                    console.error('Error updating password:', err);
                    return res.status(500).json({ message: 'Error updating password' });
                }
                res.json({ message: 'Password updated successfully' });
            });
        });
    } catch (err) {
        console.error('Error in reset-password route:', err);
        res.status(500).json({ message: 'Error processing request' });
    }
});

// Centralized Error Handling Middleware (Optional but recommended)
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err.stack);
    res.status(500).json({ message: 'Something went wrong, please try again later.' });
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});
