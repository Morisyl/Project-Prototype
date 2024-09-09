require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const path = require('path');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// JWT authentication middleware
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers['authorization']; // Get the Authorization header
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) { 
        return res.status(401).json({ message: 'No token provided' }); // No token, unauthorized
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' }); // Invalid or expired token
        }
        
        req.user = user;
        next();
    });
};

// Middleware to Blacklist JWT tokens
const blacklistedTokens = [];

function isTokenBlacklisted(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (blacklistedTokens.includes(token)) {
        return res.status(401).json({ message: 'Token is blacklisted.' });
    }
    next();
}

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));
app.use(helmet());
app.use(cors());
app.use('/booking', authenticateJWT);
app.use('/enquiries', authenticateJWT);
// app.use('/payments', authenticateJWT);

// Create a connection to the MySQL server
const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD
});

// Connect to the MySQL server
connection.connect(err => {
    if (err) {
        console.error('Error connecting to MySQL server:', err);
        return;
    }
    console.log('Connected to MySQL server.');

    // Check if the database exists
    const dbName = process.env.DB_NAME;
    connection.query(`SHOW DATABASES LIKE '${dbName}'`, (err, results) => {
        if (err) {
            console.error('Error checking database existence:', err);
            connection.end();
            return;
        }

        if (results.length === 0) {
            // Database does not exist, create it
            connection.query(`CREATE DATABASE ${dbName}`, err => {
                if (err) {
                    console.error('Error creating database:', err);
                } else {
                    console.log('Database created successfully.');
                }
                // After creating the database, connect to it and create tables
                setupDatabase();
            });
        } else {
            console.log('Database already exists.');
            // Connect to the existing database and create tables
            setupDatabase();
        }
    });
});

// Function to setup the database and create tables
async function setupDatabase() {
    return new Promise((resolve, reject) => {
        // Update the connection with the specific database
        connection.changeUser({ database: process.env.DB_NAME }, async err => {
            if (err) {
                console.error('Error selecting database:', err);
                return reject(err);
            }
            console.log('Connected to MySQL database.');

            // Promisify query for easier usage with async/await
            const query = promisify(connection.query).bind(connection);

            // Create tables if they don't exist
            const createTables = async () => {
                try {
                    const createUsersTable = `
                        CREATE TABLE IF NOT EXISTS users (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            username VARCHAR(255) NOT NULL,
                            email VARCHAR(255) UNIQUE NOT NULL,
                            password VARCHAR(255) NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    `;

                    const createBookingsTable = `
                        CREATE TABLE IF NOT EXISTS bookings (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT,
                            name VARCHAR(255) NOT NULL,
                            email VARCHAR(255) NOT NULL,
                            gender ENUM('male', 'female') NOT NULL,
                            phone_number VARCHAR(20),
                            service VARCHAR(255) NOT NULL,
                            details TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                        )
                    `;

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

                    const createBankTransferDetailsTable = `
                        CREATE TABLE IF NOT EXISTS bank_transfer_details (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            payment_id INT,
                            bank_name VARCHAR(255) NOT NULL,
                            account_number VARCHAR(20) NOT NULL,
                            transactions_code VARCHAR(10) NOT NULL,
                            FOREIGN KEY (payment_id) REFERENCES payments(id) ON DELETE CASCADE
                        )
                    `;

                    const createPayPalPaymentsTable = `
                        CREATE TABLE IF NOT EXISTS paypal_payments (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            payment_id INT,
                            payment_email VARCHAR(255) NOT NULL,
                            transaction_id VARCHAR(255) NOT NULL,
                            paypal_status ENUM('pending', 'completed') NOT NULL,
                            FOREIGN KEY (payment_id) REFERENCES payments(id) ON DELETE CASCADE
                        )
                    `;

                    const createMpesaPaymentsTable = `
                        CREATE TABLE IF NOT EXISTS mpesa_payments (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            payment_id INT,
                            mpesa_number VARCHAR(10) NOT NULL,
                            transaction_code VARCHAR(10) NOT NULL,
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
                    resolve(); // Resolve the promise when done
                } catch (error) {
                    console.error('Error creating tables:', error);
                    reject(error); // Reject the promise if there's an error
                }
            };

            // Call the createTables function
            await createTables();
        });
    });
}

// Call setupDatabase function and handle errors
setupDatabase().catch(error => {
    console.error('Error setting up database:', error);
});


// Middleware Encryption configuration
const algorithm = 'aes-256-cbc';
const encryptionKey = process.env.ENCRYPTION_KEY; // 32 bytes

// Encrypt function with unique IV for every encryption operation
function encrypt(text) {
    const iv = crypto.randomBytes(16);  // Generate a new IV each time
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(encryptionKey, 'hex'), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { iv: iv.toString('hex'), encryptedData: encrypted };
}
// Decrypt function using IV and encrypted data
function decrypt(encryptedData, iv) {
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(encryptionKey, 'hex'), Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

module.exports = { encrypt, decrypt };

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
    const { name, email, gender, phone_number, service, details } = req.body;
    const userId = req.user.id; // Get user ID from token

    const query = 'INSERT INTO bookings (user_id, name, email, gender, phone_number, service, details) VALUES (?, ?, ?, ?, ?, ?, ?)';
    connection.query(query, [userId, name, email, gender, phone_number, service, details], function (err, result) {
        if (err) {
            console.error('Error saving booking:', err);
            res.status(500).json({ message: 'Error saving booking' });
        } else {
            const bookingId = result.insertId; // Get the newly created booking ID
            res.json({ message: 'Booking saved successfully', booking_id: bookingId });
        }
    });
});

// Route to handle payment creation
app.post('/payments', authenticateJWT, async (req, res) => {
    const { booking_id } = req.body;

    if (!booking_id) {
        return res.status(400).json({ message: 'Missing booking_id.' });
    }

    try {
        // Get booking details
        const bookingDetails = await query('SELECT * FROM bookings WHERE id = ?', [booking_id]);

        if (bookingDetails.length === 0) {
            return res.status(404).json({ message: 'Booking not found.' });
        }

        // For demonstration, we're using hardcoded values for payment method and status
        const payment_method = 'credit-card'; // Example
        const payment_status = 'complete'; // Example
        const payment_amount = 100.00; // Example, you can calculate or fetch the amount from somewhere

        // Insert payment record
        await query('INSERT INTO payments (booking_id, payment_method, payment_status, payment_amount) VALUES (?, ?, ?, ?)', [booking_id, payment_method, payment_status, payment_amount]);

        res.status(201).json({ message: 'Payment record created.' });
    } catch (error) {
        res.status(500).json({ message: 'Error creating payment record.', error });
    }
});

// Enquiry route
app.post('/enquiries', authenticateJWT, async (req, res) => {
    const { name, email, message } = req.body;
    const userId = req.user.id; // Get user ID from token

    // Simple validation
    if (!name || !email || !message) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    console.log('Received enquiry:', { userId, name, email, message });

    const query = promisify(connection.query).bind(connection);

    try {
        await query('INSERT INTO enquiries (user_id, name, email, message) VALUES (?, ?, ?, ?)', [userId, name, email, message]);
        res.json({ message: 'Enquiry saved successfully' });
    } catch (err) {
        console.error('Error saving enquiry:', err);
        res.status(500).json({ message: 'Error saving enquiry', error: err.message });
    }
});



// Register Route
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        // Input validation
        if (!username || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Check if email already exists
        const checkQuery = 'SELECT * FROM users WHERE email = ?';
        const existingUser = await new Promise((resolve, reject) => {
            connection.query(checkQuery, [email], (err, results) => {
                if (err) return reject(err);
                resolve(results.length ? results[0] : null);  
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
            connection.query(insertQuery, [username, email, hashedPassword], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        // Return success message
        res.status(201).json({ message: 'Registration successful' });

    } catch (err) {
        console.error('Error during registration:', err.message);
        res.status(500).json({ message: err.message });
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM users WHERE email = ?';
    connection.query(query, [email], async (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ message: 'Error logging in' });
        }

        if (results.length === 0) {  // Explicitly check if no user is found
            return res.status(400).json({ message: 'Invalid email or password' });
        }
    
        const user = results[0];
        const match = await bcrypt.compare(password, user.password);

        if (match) {
            const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
            console.log('User found:', user); // Log user info before responding
            console.log('Password match:', match); // Log match status
            res.json({ token });
        } else {
            console.log('Invalid password attempt for user:', email); // Log failed login attempt
            res.status(400).json({ message: 'Invalid email or password' });
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


// Credit Card Payment route
app.post('/api/credit-card-payments', (req, res) => {
    const { bookingId, paymentAmount, cardNumber, expiryDate, cvc } = req.body;

    // Encrypt sensitive data
    const encryptedCardNumber = encrypt(cardNumber);  // Use the updated encrypt function with IV
    const encryptedExpiryDate = encrypt(expiryDate);
    const encryptedCvc = encrypt(cvc);

     // Dynamically use the payment amount passed from the request
    const insertPaymentQuery = 'INSERT INTO payments (booking_id, payment_method, payment_status, payment_amount) VALUES (?, ?, ?, ?)';
    connection.query(insertPaymentQuery, [bookingId, 'credit-card', 'completed', paymentAmount], (err, result) => {
        if (err) {
            console.error('Error inserting payment:', err);
            return res.status(500).json({ message: 'Error processing payment' });
        }

        const paymentId = result.insertId;


 // Insert the encrypted card details and store the IV
 const insertCreditCardPaymentQuery = 'INSERT INTO credit_card_payments (payment_id, card_number, expiry_date, cvc, iv) VALUES (?, ?, ?, ?, ?)';
 connection.query(insertCreditCardPaymentQuery, [paymentId, encryptedCardNumber.encryptedData, encryptedExpiryDate.encryptedData, encryptedCvc.encryptedData, encryptedCardNumber.iv], (err) => {
     if (err) {
         console.error('Error inserting credit card payment:', err);
         return res.status(500).json({ message: 'Error processing payment' });
     } else {
         res.json({ message: 'Payment processed successfully' });
     }
 });
});
});


// Decrypt card data when needed
app.get('/api/decrypted-card-details/:paymentId', (req, res) => {
    const paymentId = parseInt(req.params.paymentId, 10);

    const query = 'SELECT * FROM credit_card_payments WHERE payment_id = ?';
    connection.query(query, [paymentId], (err, results) => {
        if (err) {
            console.error('Error fetching card details:', err);
            return res.status(500).json({ message: 'Error fetching card details' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'Payment not found' });
        }

        const encryptedData = results[0];
        const decryptedCardNumber = decrypt(encryptedData.card_number, encryptedData.iv);
        const decryptedExpiryDate = decrypt(encryptedData.expiry_date, encryptedData.iv);
        const decryptedCvc = decrypt(encryptedData.cvc, encryptedData.iv);


        res.json({
            cardNumber: decryptedCardNumber,
            expiryDate: decryptedExpiryDate,
            cvc: decryptedCvc
        });
    });
});

// Example route for handling payments with credit card details
app.post('credit-card', authenticateJWT, async (req, res) => {
    const { booking_id, card_number, expiry_date, cvc } = req.body;

    if (!booking_id || !card_number || !expiry_date || !cvc) {
        return res.status(400).json({ message: 'Missing required fields for credit card payment.' });
    }

    try {
        // Insert payment record
        await query('INSERT INTO payments (booking_id, payment_method, payment_status, payment_amount) VALUES (?, ?, ?, ?)', [booking_id, 'credit-card', 'pending', 100.00]);
        
        // Insert credit card details
        await query('INSERT INTO credit_card_payments (payment_id, card_number, expiry_date, cvc) VALUES ((SELECT id FROM payments WHERE booking_id = ? ORDER BY id DESC LIMIT 1), ?, ?, ?)', [booking_id, card_number, expiry_date, cvc]);

        res.status(201).json({ message: 'Credit card payment record created.' });
    } catch (error) {
        res.status(500).json({ message: 'Error creating credit card payment record.', error });
    }
});

// Example route for handling payments with PayPal
app.post('paypal', authenticateJWT, async (req, res) => {
    const { booking_id, payment_email, transaction_id } = req.body;

    if (!booking_id || !payment_email || !transaction_id) {
        return res.status(400).json({ message: 'Missing required fields for PayPal payment.' });
    }

    try {
        // Insert payment record
        await query('INSERT INTO payments (booking_id, payment_method, payment_status, payment_amount) VALUES (?, ?, ?, ?)', [booking_id, 'paypal', 'pending', 100.00]);
        
        // Insert PayPal details
        await query('INSERT INTO paypal_payments (payment_id, payment_email, transaction_id) VALUES ((SELECT id FROM payments WHERE booking_id = ? ORDER BY id DESC LIMIT 1), ?, ?)', [booking_id, payment_email, transaction_id]);

        res.status(201).json({ message: 'PayPal payment record created.' });
    } catch (error) {
        res.status(500).json({ message: 'Error creating PayPal payment record.', error });
    }
});

// Example route for handling payments with bank transfer
app.post('bank-transfer', authenticateJWT, async (req, res) => {
    const { booking_id, bank_name, account_number, transactions_code } = req.body;

    if (!booking_id || !bank_name || !account_number || !transactions_code) {
        return res.status(400).json({ message: 'Missing required fields for bank transfer payment.' });
    }

    try {
        // Insert payment record
        await query('INSERT INTO payments (booking_id, payment_method, payment_status, payment_amount) VALUES (?, ?, ?, ?)', [booking_id, 'bank-transfer', 'pending', 100.00]);
        
        // Insert bank transfer details
        await query('INSERT INTO bank_transfer_details (payment_id, bank_name, account_number, transactions_code) VALUES ((SELECT id FROM payments WHERE booking_id = ? ORDER BY id DESC LIMIT 1), ?, ?, ?)', [booking_id, bank_name, account_number, transactions_code]);

        res.status(201).json({ message: 'Bank transfer payment record created.' });
    } catch (error) {
        res.status(500).json({ message: 'Error creating bank transfer payment record.', error });
    }
});

// Example route for handling payments with Mpesa
app.post('mpesa', authenticateJWT, async (req, res) => {
    const { booking_id, mpesa_number, transaction_code } = req.body;

    if (!booking_id || !mpesa_number || !transaction_code) {
        return res.status(400).json({ message: 'Missing required fields for Mpesa payment.' });
    }

    try {
        // Insert payment record
        await query('INSERT INTO payments (booking_id, payment_method, payment_status, payment_amount) VALUES (?, ?, ?, ?)', [booking_id, 'mpesa', 'pending', 100.00]);
        
        // Insert Mpesa details
        await query('INSERT INTO mpesa_payments (payment_id, mpesa_number, transaction_code) VALUES ((SELECT id FROM payments WHERE booking_id = ? ORDER BY id DESC LIMIT 1), ?, ?)', [booking_id, mpesa_number, transaction_code]);

        res.status(201).json({ message: 'Mpesa payment record created.' });
    } catch (error) {
        res.status(500).json({ message: 'Error creating Mpesa payment record.', error });
    }
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

