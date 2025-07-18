import React, { useState } from "react";
import './index.css'
import axios from "axios";
import { decryptWithAES, encryptWithAES, encryptWithPublicKey } from "./utils";

const url = import.meta.env.VITE_API_URL

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

  const fetchPublicKey = async () => {
    try {
      const response = await api.get("/get_public_key");

      if (response.data.publicKey)
        console.log("received public key \n", response.data.publicKey.slice(0, 20));
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

  const [normalResponse, setNormalResponse] = useState(null);

  const sendData = async () => {
    try {
      const requestData = { data: "Some Sensitive Data", id: 1234 };
      const response = await api.post("/test", requestData);
      setNormalResponse(response.data)
      console.log(response.data);


    } catch (error) {
      console.error("Error sending encrypted data:", error);
    }
  };

  return (
    <>
    <div className="container">
      <h1>SafeXchange</h1>
      <p className="description">
        This demo showcases secure communication between a client and a server using AES and RSA encryption.
      </p>
      <p className="description">
         <h4>Old version: <a href="https://www.npmjs.com/package/safexchange">https://www.npmjs.com/package/safexchange</a> </h4>
      </p>
      <div className="info-section">
        <h2>Why Secure Communication Matters?</h2>
        <p>
          Many startups and companies often do not implement proper server-side validations, leading to potential security loopholes. 
          In some cases, sensitive and non-disclosable data might be exposed due to poor encryption or lack of end-to-end security.
        </p>
        <p>
          This is where solutions like <strong>SafeXchange</strong> come into play. By implementing robust client-side and server-side 
          encryption using AES and RSA, sensitive information remains protected even if other security measures fail.
        </p>
        <p>
          Always ensure that your applications handle data securely, whether it's user credentials, financial data, or any other sensitive 
          information. Encryption should be a fundamental part of your development process.
        </p>
        </div>
        <br/>
        <h2>Updated version with secure workflow:</h2>
      <div className="step">
        <h2>Step 0: Send Normal Data</h2>
        <p>
          Send Data Normally
        </p>
        <button onClick={sendData} >
          Send Normal Message
        </button>
        {normalResponse && <p>Response: {JSON.stringify(normalResponse, null, 2)}</p>}
      </div>
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
      </>
  );
};

export default App;
