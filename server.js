const express = require('express');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.use(express.json({ limit: '100kb' }));
app.use(express.static(__dirname));

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'julko-store' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`JULKO STORE en ligne sur le port ${PORT}`);
});
