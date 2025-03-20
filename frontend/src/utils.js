import CryptoJS from "crypto-js";

// Encrypt data using AES-CBC
export const encryptWithAES = (key, data) => {
  console.log("\n\nBefore encrypting request: \n", data);
  
  const iv = CryptoJS.lib.WordArray.random(16);
  const encrypted = CryptoJS.AES.encrypt(data, CryptoJS.enc.Hex.parse(key), {
    iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  console.log("\n\nAfter encrypting request: \n", {
    iv: iv.toString(CryptoJS.enc.Hex),
    encryptedData: encrypted.ciphertext.toString(CryptoJS.enc.Hex), // Hex format
  });
  

  // Convert encrypted data to Hex (instead of Base64)
  return {
    iv: iv.toString(CryptoJS.enc.Hex),
    encryptedData: encrypted.ciphertext.toString(CryptoJS.enc.Hex), // Hex format
  };
};

// Decrypt data using AES-CBC
export const decryptWithAES = (key, iv, encryptedData) => {

  console.log("\n\nBefore Decrypting Response:\n", {iv, encryptedData});

  const decrypted = CryptoJS.AES.decrypt(
    { ciphertext: CryptoJS.enc.Hex.parse(encryptedData) }, // Convert back from Hex
    CryptoJS.enc.Hex.parse(key),
    {
      iv: CryptoJS.enc.Hex.parse(iv),
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    }
  ).toString(CryptoJS.enc.Utf8);
  console.log("\n\nAfter Decrypting Response:\n", JSON.parse(decrypted));
  
  try {
    return JSON.parse(decrypted); // ✅ Parse JSON before returning
  } catch (error) {
    console.error("Decryption failed or invalid JSON:", error);
    return null; // Return null if parsing fails
  }
};




import forge from "node-forge";

// Encrypt AES key using RSA Public Key
export const encryptWithPublicKey = (publicKey, aesKey) => {
  try {
    const rsa = forge.pki.publicKeyFromPem(publicKey);
    const encrypted = rsa.encrypt(aesKey, "RSA-OAEP");
    return forge.util.encode64(encrypted);
  } catch (error) {
    console.error("RSA encryption error:", error);
    return null;
  }
};
