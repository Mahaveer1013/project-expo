import React, { useState } from "react";
import './index.css'
import axios from "axios";
import { decryptWithAES, encryptWithAES, encryptWithPublicKey } from "./utils";

const url = "http://localhost:3000"

const api = axios.create({
  baseURL: url,
  withCredentials: true,
});

const encryptedApi = axios.create({
  baseURL: url,
  withCredentials: true,
});

encryptedApi.interceptors.request.use(config => {
  config.headers["x-data-encrypted"] = "true";
  return config;
});

encryptedApi.interceptors.response.use(response => {
  if (response.headers["x-data-encrypted"] === "true") {
    response.data.isEncrypted = true;
  }
  return response.data;
});

const App = () => {
  const [publicKey, setPublicKey] = useState(null);
  const [aesKey, setAesKey] = useState(null);
  const [decryptedData, setDecryptedData] = useState(null);

  // useEffect(() => {
  //   fetchPublicKey();
  // }, []);

  const fetchPublicKey = async () => {
    try {
      const response = await api.get("/get_public_key");
      
      if (response.data.publicKey)
        console.log("received public key \n", response.data.publicKey.slice(0,20));
        setPublicKey(response.data.publicKey);
    } catch (error) {
      console.error("Error fetching public key:", error);
    }
  };

  const generateAESKey = async () => {
    const key = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const exportedKey = await window.crypto.subtle.exportKey("raw", key);

    const keyArray = new Uint8Array(exportedKey);
    return Array.from(keyArray).map(byte => byte.toString(16).padStart(2, "0")).join("");
  };

  const setSessionKey = async () => {
    if (!publicKey) return;
    try {
      const aesKeyGenerated = await generateAESKey();
      const encryptedAESKey = encryptWithPublicKey(publicKey, aesKeyGenerated);

      await api.post("/set_session", { encryptedAESKey });
      setAesKey(aesKeyGenerated);
    } catch (error) {
      console.error("Error setting session key:", error);
    }
  };

  const sendEncryptedData = async () => {
    if (!aesKey) return;

    try {
      const requestData = { message: "Hello, Secure Server!" };

      const encryptedRequestData = encryptWithAES(aesKey, JSON.stringify(requestData));

      const response = await encryptedApi.post("/test", encryptedRequestData);

      if (response.isEncrypted) {
        const { iv, encryptedData } = response;
        setDecryptedData(decryptWithAES(aesKey, iv, encryptedData));
      }
      else
        setDecryptedData(response)
    } catch (error) {
      console.error("Error sending encrypted data:", error);
    }
  };

  return (
    <div className="container">
      <h1>Secure Communication Demo</h1>
      <p className="description">
        This demo showcases secure communication between a client and a server using AES and RSA encryption.
      </p>

      <div className="step">
        <h2>Step 1: Fetch Server's Public Key</h2>
        <p>
          The server's public key is required to securely send the AES key to the server.
        </p>
        <button onClick={fetchPublicKey} disabled={publicKey}>
          {publicKey ? "Public Key Fetched" : "Fetch Public Key"}
        </button>
        {publicKey && <p>Public Key: {publicKey}</p>}
      </div>

      <div className="step">
        <h2>Step 2: Set AES Session Key</h2>
        <p>
          Generate an AES key, encrypt it with the server's public key, and send it to the server.
        </p>
        <button onClick={setSessionKey} disabled={!publicKey || aesKey}>
          {aesKey ? "AES Key Set" : "Set AES Key"}
        </button>
          {aesKey && <p>AES Key: {aesKey}</p>}
      </div>

      <div className="step">
        <h2>Step 3: Send Encrypted Data</h2>
        <p>
          Encrypt a message using the AES key and send it to the server. The server will decrypt and respond.
        </p>
        <button onClick={sendEncryptedData} disabled={!aesKey}>
          Send Encrypted Message
        </button>
      </div>

      {decryptedData && (
        <div className="result">
          <h2>Server Response</h2>
          <p>Decrypted data received from the server:</p>
          <pre>{decryptedData}</pre>
        </div>
      )}
    </div>
  );
};

export default App;
