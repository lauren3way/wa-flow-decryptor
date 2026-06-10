const express = require('express');
const crypto = require('crypto');
const axios = require('axios');

const app = express();
app.use(express.json());

const PRIVATE_KEY = process.env.PRIVATE_KEY.replace(/\\n/g, '\n');
const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;

function decryptRequest(body) {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

  const decryptedAesKey = crypto.privateDecrypt(
    {
      key: PRIVATE_KEY,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(encrypted_aes_key, 'base64')
  );

  const iv = Buffer.from(initial_vector, 'base64');
  const decipher = crypto.createDecipheriv('aes-128-gcm', decryptedAesKey, iv);

  const encryptedData = Buffer.from(encrypted_flow_data, 'base64');
  const TAG_LENGTH = 16;
  const encryptedBody = encryptedData.slice(0, -TAG_LENGTH);
  const authTag = encryptedData.slice(-TAG_LENGTH);

  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encryptedBody),
    decipher.final(),
  ]);

  return {
    decryptedBody: JSON.parse(decrypted.toString('utf-8')),
    aesKey: decryptedAesKey,
    iv: iv
  };
}

function encryptResponse(response, aesKey, iv) {
  const flippedIv = Buffer.alloc(iv.length);
  for (let i = 0; i < iv.length; i++) {
    flippedIv[i] = ~iv[i];
  }

  const cipher = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
  const data = Buffer.from(JSON.stringify(response));
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([encrypted, authTag]).toString('base64');
}

app.post('/flow', async (req, res) => {
  try {
    const { decryptedBody, aesKey, iv } = decryptRequest(req.body);
    console.log('Decrypted payload:', JSON.stringify(decryptedBody));

    // ── Handle Meta health check ping (arrives encrypted) ──
    if (decryptedBody.action === 'ping') {
      console.log('Health check ping received');
      const encryptedResponse = encryptResponse(
        { data: { status: 'active' } },
        aesKey,
        iv
      );
      res.set('Content-Type', 'text/plain');
      return res.send(encryptedResponse);
    }

    // ── Forward plain JSON to Make ──
    await axios.post(MAKE_WEBHOOK_URL, decryptedBody);

    // ── Send encrypted SUCCESS response back to Meta ──
    const encryptedResponse = encryptResponse(
      { screen: 'SUCCESS', data: {} },
      aesKey,
      iv
    );
    res.set('Content-Type', 'text/plain');
    return res.send(encryptedResponse);

  } catch (err) {
    console.error('Error:', err.message);
    return res.status(500).json({ error: 'Decryption failed' });
  }
});

app.get('/health', (req, res) => res.send('OK'));

app.listen(process.env.PORT || 3000, () => {
  console.log('Decryption server running');
});
