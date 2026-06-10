const express = require('express');
const crypto = require('crypto');
const axios = require('axios');

const app = express();
app.use(express.json());

const PRIVATE_KEY = process.env.PRIVATE_KEY.replace(/\\n/g, '\n');
const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;

function decryptRequest(body) {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

  // Decrypt the AES key using your RSA private key
  const decryptedAesKey = crypto.privateDecrypt(
    {
      key: PRIVATE_KEY,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(encrypted_aes_key, 'base64')
  );

  // Decrypt the flow data using the AES key
  const iv = Buffer.from(initial_vector, 'base64');
  const decipher = crypto.createDecipheriv(
    'aes-128-gcm',
    decryptedAesKey,
    iv
  );

  const encryptedData = Buffer.from(encrypted_flow_data, 'base64');
  const TAG_LENGTH = 16;
  const encryptedBody = encryptedData.slice(0, -TAG_LENGTH);
  const authTag = encryptedData.slice(-TAG_LENGTH);

  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encryptedBody),
    decipher.final(),
  ]);

  return JSON.parse(decrypted.toString('utf-8'));
}

function encryptResponse(response, aesKeyBuffer, iv) {
  // Flip the IV for the response
  const flippedIv = Buffer.alloc(iv.length);
  for (let i = 0; i < iv.length; i++) {
    flippedIv[i] = ~iv[i];
  }

  const cipher = crypto.createCipheriv('aes-128-gcm', aesKeyBuffer, flippedIv);
  const data = Buffer.from(JSON.stringify(response));

  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([encrypted, authTag]).toString('base64');
}

app.post('/flow', async (req, res) => {
  try {
    const { encrypted_aes_key, initial_vector } = req.body;

    // Decrypt AES key (needed for response encryption too)
    const decryptedAesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encrypted_aes_key, 'base64')
    );

    const iv = Buffer.from(initial_vector, 'base64');
    const decryptedBody = decryptRequest(req.body);

    console.log('Decrypted Flow payload:', JSON.stringify(decryptedBody));

    // Forward plain JSON to Make
    await axios.post(MAKE_WEBHOOK_URL, decryptedBody);

    // Send encrypted SUCCESS response back to Meta
    const responsePayload = {
      screen: 'SUCCESS',
      data: {}
    };

    const encryptedResponse = encryptResponse(responsePayload, decryptedAesKey, iv);

    res.json({ encrypted_flow_data: encryptedResponse });

  } catch (err) {
    console.error('Decryption error:', err);
    res.status(500).json({ error: 'Decryption failed' });
  }
});

app.get('/health', (req, res) => res.send('OK'));

app.listen(process.env.PORT || 3000, () => {
  console.log('Decryption server running');
});
