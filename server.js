const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');
const argon2 = require('argon2');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || 'julko-store.db';
const ADMIN_SETUP_TOKEN = process.env.ADMIN_SETUP_TOKEN;
const db = new DatabaseSync(DB_PATH);

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'client' CHECK(role IN ('client','admin')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

app.use(express.json({limit:'50kb'}));
app.use(express.urlencoded({extended:false,limit:'50kb'}));
app.use(express.static(__dirname));

const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function adminExists(){return !!db.prepare("SELECT 1 FROM users WHERE role='admin' AND active=1 LIMIT 1").get();}
function page(message='') {return `<!doctype html><html lang="fr"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Création admin JULKO STORE</title><style>body{font-family:Arial;background:#0a0a0a;color:#fff;margin:0;padding:24px}.box{max-width:520px;margin:7vh auto;background:#171717;border:1px solid #333;border-radius:24px;padding:24px}h1{color:#d4af37}label{display:block;margin:14px 0 6px}input{width:100%;box-sizing:border-box;padding:13px;border-radius:12px;border:1px solid #444;background:#0f0f0f;color:#fff}button{width:100%;margin-top:20px;padding:14px;border:0;border-radius:12px;background:#d4af37;color:#111;font-weight:800}.msg{margin-top:14px;color:#ffd76a}.note{font-size:13px;color:#bbb}</style><div class="box"><h1>JULKO STORE</h1><h2>Créer le premier administrateur</h2><p class="note">Cette page se désactive automatiquement dès qu'un administrateur actif existe.</p><form method="post" action="/setup-admin"><label>Nom</label><input name="name" required minlength="2"><label>Numéro de téléphone</label><input name="phone" required minlength="8" inputmode="tel"><label>Mot de passe</label><input name="password" type="password" required minlength="12"><label>Code d'installation privé</label><input name="setupToken" type="password" required><button>Créer mon compte administrateur</button></form>${message?`<div class="msg">${esc(message)}</div>`:''}</div></html>`;}

app.get('/', (_req,res)=>res.sendFile(path.join(__dirname,'index.html')));
app.get('/health',(_req,res)=>res.json({ok:true,service:'julko-store'}));
app.get('/setup-admin',(_req,res)=>{if(adminExists()) return res.status(403).send('Configuration administrateur déjà terminée.');if(!ADMIN_SETUP_TOKEN)return res.status(503).send('ADMIN_SETUP_TOKEN non configuré sur Railway.');res.send(page());});
app.post('/setup-admin',async(req,res)=>{try{if(adminExists())return res.status(403).send('Configuration administrateur déjà terminée.');if(!ADMIN_SETUP_TOKEN)return res.status(503).send('ADMIN_SETUP_TOKEN non configuré.');const supplied=String(req.body.setupToken||'');const a=Buffer.from(supplied),b=Buffer.from(ADMIN_SETUP_TOKEN);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(401).send(page('Code d’installation incorrect.'));const name=String(req.body.name||'').trim(),phone=String(req.body.phone||'').trim(),password=String(req.body.password||'');if(name.length<2||phone.length<8||password.length<12)return res.status(400).send(page('Vérifie le nom, le téléphone et utilise un mot de passe d’au moins 12 caractères.'));const hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});db.prepare("INSERT INTO users(name,phone,password_hash,role,active) VALUES (?,?,?,'admin',1)").run(name,phone,hash);res.send('<!doctype html><html lang="fr"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:Arial;padding:30px"><h1>Compte administrateur créé ✅</h1><p>La page de création est maintenant verrouillée.</p><p>Tu peux fermer cette page.</p></body></html>');}catch(e){res.status(400).send(page('Création impossible. Vérifie que le numéro n’est pas déjà utilisé.'));}});

app.listen(PORT,'0.0.0.0',()=>console.log(`JULKO STORE: ${PORT}`));
