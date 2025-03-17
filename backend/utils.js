const crypto = require('crypto');

// Generate RSA key pair
function generateKeyPair(modulusLength = 2048) {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

// Encrypt data with RSA public key
function encryptWithPublicKey(publicKey, data) {
  return crypto.publicEncrypt(publicKey, Buffer.from(data)).toString('base64');
}

// Decrypt data with RSA private key
function decryptWithPrivateKey(privateKey, encryptedData) {
  return crypto.privateDecrypt(privateKey, Buffer.from(encryptedData, 'base64')).toString();
}

// Generate a random AES key
function generateAESKey(keyLength = 32) {
  return crypto.randomBytes(keyLength).toString('hex');
}

// Encrypt data with AES key
function encryptWithAES(key, data) {
  console.log('Before Encrypting response: ', data);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  console.log('After Encrypting response: ', { iv: iv.toString('hex'), encryptedData: encrypted });
  return { iv: iv.toString('hex'), encryptedData: encrypted };
}

// Decrypt data with AES key
function decryptWithAES(key, iv, encryptedData) {
  console.log('Before Decrypting Request: ', encryptedData);
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  console.log('After Decrypting Request: ', decrypted);
  return decrypted;
}

module.exports = {
  encryptWithPublicKey,
  decryptWithPrivateKey,
  generateKeyPair,
  generateAESKey,
  encryptWithAES,
  decryptWithAES,
};