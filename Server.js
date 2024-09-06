require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const path = require('path');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname))); // Serve static files from the public directory
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

    // Promisify query for easier usage with async/await
    const query = promisify(db.query).bind(db);
    
    // Create tables if they don't exist
    const createTables = async () => {
        try {
            // Users Table
            const createUsersTable = `
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `;
    
            // Bookings Table
            const createBookingsTable = `
                CREATE TABLE IF NOT EXISTS bookings (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) NOT NULL,
                    gender ENUM('male', 'female') NOT NULL,
                    home_phone VARCHAR(20),
                    office_phone VARCHAR(20),
                    service VARCHAR(255) NOT NULL,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            `;
    
            // Enquiries Table
            const createEnquiriesTable = `
                CREATE TABLE IF NOT EXISTS enquiries (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            `;
    
            // Payments Table
            const createPaymentsTable = `
                CREATE TABLE IF NOT EXISTS payments (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    booking_id INT,
                    payment_method ENUM('credit-card', 'paypal', 'bank-transfer', 'mpesa') NOT NULL,
                    payment_status ENUM('pending', 'completed', 'failed') NOT NULL,
                    payment_amount DECIMAL(10, 2) NOT NULL,
                    payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (booking_id) REFERENCES bookings(id) ON DELETE CASCADE
                )
            `;
    
            // Credit Card Payments Table
            const createCreditCardPaymentsTable = `
                CREATE TABLE IF NOT EXISTS credit_card_payments (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    payment_id INT,
                    card_number VARCHAR(20) NOT NULL,
                    expiry_date VARCHAR(5) NOT NULL,
                    cvc VARCHAR(4) NOT NULL,
                    FOREIGN KEY (payment_id) REFERENCES payments(id) ON DELETE CASCADE
                )
            `;
    
            // Bank Transfer Details Table
            const createBankTransferDetailsTable = `
                CREATE TABLE IF NOT EXISTS bank_transfer_details (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    payment_id INT,
                    bank_name VARCHAR(255) NOT NULL,
                    account_number VARCHAR(20) NOT NULL,
                    sort_code VARCHAR(10) NOT NULL,
                    phone_number VARCHAR(20),
                    transaction_cost DECIMAL(10, 2),
                    FOREIGN KEY (payment_id) REFERENCES payments(id) ON DELETE CASCADE
                )
            `;
    
            // PayPal Payments Table
            const createPayPalPaymentsTable = `
                CREATE TABLE IF NOT EXISTS paypal_payments (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    payment_id INT,
                    transaction_id VARCHAR(255) NOT NULL,
                    paypal_status ENUM('pending', 'completed') NOT NULL,
                    FOREIGN KEY (payment_id) REFERENCES payments(id) ON DELETE CASCADE
                )
            `;
    
            // Mpesa Payments Table
            const createMpesaPaymentsTable = `
                CREATE TABLE IF NOT EXISTS mpesa_payments (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    payment_id INT,
                    mpesaNumber VARCHAR(10) NOT NULL,
                    transactionCode VARCHAR(10) NOT NULL,
                    FOREIGN KEY (payment_id) REFERENCES payments(id) ON DELETE CASCADE
                )
            `;
    
            // Execute all table creation queries
            await query(createUsersTable);
            await query(createBookingsTable);
            await query(createEnquiriesTable);
            await query(createPaymentsTable);
            await query(createCreditCardPaymentsTable);
            await query(createBankTransferDetailsTable);
            await query(createPayPalPaymentsTable);
            await query(createMpesaPaymentsTable);
     
            console.log('All tables created successfully!');
        } catch (error) {
            console.error('Error creating tables:', error);
        }
    }
    
    // Call the createTables function
    createTables();
});

// Middleware to verify JWT tokens
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (token == null) return res.sendStatus(401);
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};
const blacklistedTokens = []; // Assuming you store blacklisted tokens here

function isTokenBlacklisted(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token from Authorization header
    if (blacklistedTokens.includes(token)) {
        return res.status(401).json({ message: 'Token is blacklisted.' });
    }
    next(); // Continue to the next middleware or route handler if token is not blacklisted
}
module.exports = isTokenBlacklisted;

// Routes
// Serve HTML files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Booking route
app.post('/booking', authenticateJWT, (req, res) => {
    const { name, email, gender, homePhone, officePhone, service, details } = req.body;
    const userId = req.user.id; // Get user ID from token

    const query = 'INSERT INTO bookings (user_id, name, email, gender, home_phone, office_phone, service, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
    db.query(query, [userId, name, email, gender, homePhone, officePhone, service, details], (err) => {
        if (err) {
            console.error('Error saving booking:', err);
            res.status(500).json({ message: 'Error saving booking' });
        } else {
            res.json({ message: 'Booking saved successfully' });
        }
    });
});

// Enquiry route
app.post('/enquiries', authenticateJWT, (req, res) => {
    const { name, email, message } = req.body;
    const userId = req.user.id; // Get user ID from token

    const query = 'INSERT INTO enquiries (user_id, name, email, message) VALUES (?, ?, ?, ?)';
    db.query(query, [userId, name, email, message], (err) => {
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
        // Input validation
        if (!username || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Check if email already exists
        const checkQuery = 'SELECT * FROM users WHERE email = ?';
        const [existingUser] = await new Promise((resolve, reject) => {
            db.query(checkQuery, [email], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the new user
        const insertQuery = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
        await new Promise((resolve, reject) => {
            db.query(insertQuery, [username, email, hashedPassword], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        // Return success message
        res.status(201).json({ message: 'Registration successful' });

    } catch (err) {
        console.error('Error during registration:', err);
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
                const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
                    expiresIn: '1h'
                });
                res.json({ token });
            } else {
                res.status(400).json({ message: 'Invalid email or password' });
            }
        } catch (err) {
            console.error('Error comparing passwords:', err);
            res.status(500).json({ message: 'Error logging in' });
        }
    });
});

// Logout endpoint: Blacklists the token
app.post('/logout', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(400).json({ message: 'Token is required for logout' });
    }

    // Blacklist the token
    blacklistedTokens.push(token);
    res.json({ message: 'Successfully logged out' });
});

// Example protected route with blacklist check
app.post('/protected', isTokenBlacklisted, (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    jwt.verify(token, 'secretkey', (err, user) => {
        if (err) return res.sendStatus(403);
        res.json({ message: `Hello, ${user.email}. You accessed a protected route!` });
    });
});


// Payment routes
app.post('/payments', authenticateJWT, (req, res) => {
    const { bookingId, paymentMethod, paymentStatus, paymentAmount } = req.body;
    const userId = req.user.id; // Get user ID from token

    const query = 'INSERT INTO payments (booking_id, payment_method, payment_status, payment_amount, user_id) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [bookingId, paymentMethod, paymentStatus, paymentAmount, userId], (err) => {
        if (err) {
            console.error('Error processing payment:', err);
            res.status(500).json({ message: 'Error processing payment' });
        } else {
            res.json({ message: 'Payment processed successfully' });
        }
    });
});

// Credit Card Payment route
app.post('/credit-card-payments', authenticateJWT, (req, res) => {
    const { paymentId, cardNumber, expiryDate, cvc } = req.body;
    const userId = req.user.id; // Get user ID from token

    const query = 'INSERT INTO credit_card_payments (payment_id, card_number, expiry_date, cvc, user_id) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [paymentId, cardNumber, expiryDate, cvc, userId], (err) => {
        if (err) {
            console.error('Error saving credit card payment:', err);
            res.status(500).json({ message: 'Error saving credit card payment' });
        } else {
            res.json({ message: 'Credit card payment saved successfully' });
        }
    });
});

// Bank Transfer Details route
app.post('/bank-transfer-details', authenticateJWT, (req, res) => {
    const { paymentId, bankName, accountNumber, sortCode } = req.body;
    const userId = req.user.id; // Get user ID from token

    const query = 'INSERT INTO bank_transfer_details (payment_id, bank_name, account_number, sort_code, user_id) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [paymentId, bankName, accountNumber, sortCode, userId], (err) => {
        if (err) {
            console.error('Error saving bank transfer details:', err);
            res.status(500).json({ message: 'Error saving bank transfer details' });
        } else {
            res.json({ message: 'Bank transfer details saved successfully' });
        }
    });
});

// PayPal Payment route
app.post('/paypal-payments', authenticateJWT, (req, res) => {
    const { paymentId, transactionId, paypalStatus } = req.body;
    const userId = req.user.id; // Get user ID from token

    const query = 'INSERT INTO paypal_payments (payment_id, transaction_id, paypal_status, user_id) VALUES (?, ?, ?, ?)';
    db.query(query, [paymentId, transactionId, paypalStatus, userId], (err) => {
        if (err) {
            console.error('Error saving PayPal payment:', err);
            res.status(500).json({ message: 'Error saving PayPal payment' });
        } else {
            res.json({ message: 'PayPal payment saved successfully' });
        }
    });
});

// Mpesa Payment route
app.post('/mpesa-payments', authenticateJWT, (req, res) => {
    const { paymentId, mpesaNumber, transactionCode } = req.body;
    const userId = req.user.id; // Get user ID from token

    const query = 'INSERT INTO mpesa_payments (payment_id, mpesa_Number, transaction_Code) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [paymentId, mpesaNumber, transactionCode], (err) => {
        if (err) {
            console.error('Error saving Mpesa payment:', err);
            res.status(500).json({ message: 'Error saving Mpesa payment' });
        } else {
            res.json({ message: 'Mpesa payment saved successfully' });
        }
    });
});

// Route to get user details
app.get('/api/get-user/:username', (req, res) => {
    const username = req.params.username;
    // Replace this with your actual logic to fetch user details
    const user = user.find(u => u.username === username);

    if (user) {
        res.json({
            userId: user.id
        });
    } else {
        res.status(404).json({ message: 'User not found' });
    }
});

// Route to get booking details
app.get('/api/get-booking-details/:userId', (req, res) => {
    const userId = parseInt(req.params.userId, 10);
    // Replace this with your actual logic to fetch booking details
    const booking = bookings.find(b => b.user_id === userId);

    if (booking) {
        res.json({
            bookingId: booking.id,
            paymentAmount: booking.amount
        });
    } else {
        res.status(404).json({ message: 'Booking not found' });
    }
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

