const crypto = require('crypto');

// Generate a 32-byte (256-bit) key for AES-256-CBC
const key = crypto.randomBytes(32).toString('hex');

console.log('Encryption Key:', key);
