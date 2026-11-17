const express = require('express');
const crypto = require('crypto');
const Database = require('node:sqlite').DatabaseSync;
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const WAVE_API_KEY = process.env.WAVE_API_KEY;
const WAVE_WEBHOOK_SECRET = process.env.WAVE_WEBHOOK_SECRET;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const db = new Database(process.env.DB_PATH || 'julko-store.db');

db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, phone TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'client' CHECK(role IN ('client','admin')),
  active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, brand TEXT, price_xof INTEGER NOT NULL CHECK(price_xof > 0),
  stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0), image_url TEXT, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, phone TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending_payment',
  total_xof INTEGER NOT NULL CHECK(total_xof > 0), wave_checkout_id TEXT UNIQUE,
  wave_transaction_id TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(customer_id) REFERENCES customers(id)
);
CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL, product_id INTEGER NOT NULL, quantity INTEGER NOT NULL CHECK(quantity > 0),
  unit_price_xof INTEGER NOT NULL CHECK(unit_price_xof > 0),
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY(product_id) REFERENCES products(id)
);
CREATE TABLE IF NOT EXISTS webhook_events (
  event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

app.post('/webhooks/wave', express.raw({ type: 'application/json' }), (req, res) => {
  try {
    if (!WAVE_WEBHOOK_SECRET) return res.status(503).send('Webhook non configure');
    const rawBody = req.body.toString('utf8');
    if (!verifyWaveSignature(rawBody, req.get('Wave-Signature') || '', WAVE_WEBHOOK_SECRET)) return res.status(401).send('Signature invalide');
    const event = JSON.parse(rawBody);
    const eventId = String(event.id || '');
    if (!eventId) return res.status(400).send('Event ID manquant');
    const inserted = db.prepare('INSERT OR IGNORE INTO webhook_events(event_id,event_type) VALUES (?,?)').run(eventId, String(event.type || 'unknown'));
    if (inserted.changes === 0) return res.status(200).send('OK');
    if (event.type === 'checkout.session.completed') {
      const checkoutId = event.data?.id;
      const transactionId = event.data?.transaction_id || null;
      if (checkoutId) db.prepare("UPDATE orders SET status='paid', wave_transaction_id=? WHERE wave_checkout_id=?").run(transactionId, checkoutId);
    }
    return res.status(200).send('OK');
  } catch (e) { console.error(e); return res.status(400).send('Webhook invalide'); }
});

app.use(express.json({ limit: '100kb' }));

// Servir la boutique et le tableau de bord admin
app.use(express.static(path.join(__dirname, 'public')));
app.use('/admin', express.static(path.join(__dirname, 'admin')));
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (_req, res) => res.sendFile(path.join(__dirname, 'admin', 'index.html')));
app.get('/health', (_req,res)=>res.json({ok:true,database:true}));
app.get('/api/products', (_req,res)=>res.json(db.prepare('SELECT * FROM products WHERE active=1 ORDER BY price_xof ASC').all()));

function issueToken(user){
  if(!JWT_SECRET) throw new Error('JWT_SECRET non configure');
  return jwt.sign({sub:String(user.id),role:user.role},JWT_SECRET,{algorithm:'HS256',expiresIn:'2h',issuer:'julko-store'});
}
function requireAuth(role){return (req,res,next)=>{try{const h=req.get('Authorization')||'';if(!h.startsWith('Bearer '))return res.status(401).json({error:'Connexion requise'});const token=h.slice(7);const claims=jwt.verify(token,JWT_SECRET,{algorithms:['HS256'],issuer:'julko-store'});const u=db.prepare('SELECT id,name,phone,role,active FROM users WHERE id=?').get(Number(claims.sub));if(!u||!u.active||(role&&u.role!==role))return res.status(403).json({error:'Acces refuse'});req.user=u;next();}catch{return res.status(401).json({error:'Session invalide'});}}}
app.post('/api/auth/register', async (req,res)=>{try{const name=String(req.body.name||'').trim(),phone=String(req.body.phone||'').trim(),password=String(req.body.password||'');if(name.length<2||phone.length<8||password.length<10)return res.status(400).json({error:'Nom, telephone ou mot de passe invalide'});const hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});const r=db.prepare("INSERT INTO users(name,phone,password_hash,role) VALUES (?,?,?,'client')").run(name,phone,hash);const user=db.prepare('SELECT id,name,phone,role FROM users WHERE id=?').get(r.lastInsertRowid);res.status(201).json({user,token:issueToken(user)});}catch(e){if(String(e).includes('UNIQUE'))return res.status(409).json({error:'Numero deja utilise'});res.status(400).json({error:'Inscription impossible'});}});
app.post('/api/auth/login', async (req,res)=>{const phone=String(req.body.phone||'').trim(),password=String(req.body.password||'');const u=db.prepare('SELECT * FROM users WHERE phone=? AND active=1').get(phone);if(!u||!(await argon2.verify(u.password_hash,password).catch(()=>false)))return res.status(401).json({error:'Identifiants invalides'});res.json({user:{id:u.id,name:u.name,phone:u.phone,role:u.role},token:issueToken(u)});});
app.get('/api/me',requireAuth(),(req,res)=>res.json(req.user));
app.get('/api/admin/overview',requireAuth('admin'),(_req,res)=>res.json({products:db.prepare('SELECT COUNT(*) n FROM products').get().n,orders:db.prepare('SELECT COUNT(*) n FROM orders').get().n,customers:db.prepare('SELECT COUNT(*) n FROM users WHERE role=\'client\'').get().n}));

app.get('/api/admin/orders', requireAuth('admin'), (_req,res)=>{const orders=db.prepare(`SELECT o.id,o.status,o.total_xof,o.created_at,c.name customer_name,c.phone customer_phone FROM orders o JOIN customers c ON c.id=o.customer_id ORDER BY o.id DESC`).all();const itemQ=db.prepare(`SELECT oi.quantity,oi.unit_price_xof,p.name,p.brand FROM order_items oi JOIN products p ON p.id=oi.product_id WHERE oi.order_id=?`);res.json(orders.map(o=>({...o,items:itemQ.all(o.id)})));});
app.patch('/api/admin/orders/:id/status', requireAuth('admin'), (req,res)=>{const allowed=['pending_payment','confirmed','preparing','out_for_delivery','delivered','cancelled'];const status=String(req.body.status||'');const id=Number(req.params.id);if(!allowed.includes(status))return res.status(400).json({error:'Statut invalide'});const x=db.prepare('UPDATE orders SET status=? WHERE id=?').run(status,id);if(!x.changes)return res.status(404).json({error:'Commande introuvable'});res.json({ok:true,id,status});});
app.post('/api/admin/orders/:id/confirm-delivery-payment', requireAuth('admin'), (req,res)=>{const id=Number(req.params.id);const x=db.prepare("UPDATE orders SET status='delivered', wave_transaction_id=COALESCE(wave_transaction_id,'WAVE_DELIVERY_CONFIRMED') WHERE id=? AND status!='cancelled'").run(id);if(!x.changes)return res.status(404).json({error:'Commande introuvable ou annulee'});res.json({ok:true,id,status:'delivered',payment:'wave_on_delivery_confirmed'});});

app.post('/api/admin/products', requireAuth('admin'), (req,res)=>{try{const name=String(req.body.name||'').trim(),brand=String(req.body.brand||'').trim(),image=String(req.body.image_url||'').trim();const price=Number(req.body.price_xof),stock=Number(req.body.stock);if(!name||!Number.isInteger(price)||price<1||!Number.isInteger(stock)||stock<0)return res.status(400).json({error:'Produit invalide'});const x=db.prepare('INSERT INTO products(name,brand,price_xof,stock,image_url) VALUES (?,?,?,?,?)').run(name,brand,price,stock,image||null);res.status(201).json(db.prepare('SELECT * FROM products WHERE id=?').get(x.lastInsertRowid));}catch(e){res.status(400).json({error:'Ajout impossible'});}});
app.put('/api/admin/products/:id', requireAuth('admin'), (req,res)=>{const id=Number(req.params.id),name=String(req.body.name||'').trim(),brand=String(req.body.brand||'').trim(),image=String(req.body.image_url||'').trim(),price=Number(req.body.price_xof),stock=Number(req.body.stock);if(!Number.isInteger(id)||!name||!Number.isInteger(price)||price<1||!Number.isInteger(stock)||stock<0)return res.status(400).json({error:'Produit invalide'});const x=db.prepare('UPDATE products SET name=?,brand=?,price_xof=?,stock=?,image_url=? WHERE id=?').run(name,brand,price,stock,image||null,id);if(!x.changes)return res.status(404).json({error:'Produit introuvable'});res.json(db.prepare('SELECT * FROM products WHERE id=?').get(id));});
app.delete('/api/admin/products/:id', requireAuth('admin'), (req,res)=>{const id=Number(req.params.id);const used=db.prepare('SELECT 1 FROM order_items WHERE product_id=? LIMIT 1').get(id);if(used){db.prepare('UPDATE products SET active=0 WHERE id=?').run(id);return res.json({ok:true,archived:true});}const x=db.prepare('DELETE FROM products WHERE id=?').run(id);if(!x.changes)return res.status(404).json({error:'Produit introuvable'});res.json({ok:true,deleted:true});});

app.post('/api/orders', (req,res) => {
  try {
    const { customer, items } = req.body;
    if (!customer?.name || !customer?.phone || !Array.isArray(items) || !items.length) return res.status(400).json({error:'Commande invalide'});
    const create = db.transaction(() => {
      db.prepare('INSERT INTO customers(name,phone) VALUES (?,?) ON CONFLICT(phone) DO UPDATE SET name=excluded.name').run(customer.name.trim(), customer.phone.trim());
      const c = db.prepare('SELECT id FROM customers WHERE phone=?').get(customer.phone.trim());
      let total = 0; const checked=[];
      for (const item of items) {
        const p=db.prepare('SELECT id,price_xof,stock FROM products WHERE id=? AND active=1').get(Number(item.productId));
        const qty=Number(item.quantity);
        if(!p || !Number.isInteger(qty) || qty<1 || p.stock<qty) throw new Error('Produit ou stock invalide');
        total += p.price_xof*qty; checked.push({p,qty});
      }
      const o=db.prepare('INSERT INTO orders(customer_id,total_xof) VALUES (?,?)').run(c.id,total);
      const add=db.prepare('INSERT INTO order_items(order_id,product_id,quantity,unit_price_xof) VALUES (?,?,?,?)');
      checked.forEach(x=>add.run(o.lastInsertRowid,x.p.id,x.qty,x.p.price_xof));
      return {orderId:Number(o.lastInsertRowid),total};
    });
    res.status(201).json(create());
  } catch(e){res.status(400).json({error:e.message});}
});

app.post('/api/wave/checkout', async (req,res) => {
  try {
    if(!WAVE_API_KEY || !PUBLIC_BASE_URL) return res.status(503).json({error:'Wave non configure'});
    const orderId=Number(req.body.orderId);
    const order=db.prepare("SELECT id,total_xof,status FROM orders WHERE id=?").get(orderId);
    if(!order || order.status!=='pending_payment') return res.status(400).json({error:'Commande introuvable ou deja traitee'});
    const payload={amount:String(order.total_xof),currency:'XOF',success_url:`${PUBLIC_BASE_URL}/paiement/succes`,error_url:`${PUBLIC_BASE_URL}/paiement/erreur`,client_reference:`JULKO-${order.id}`};
    const wr=await fetch('https://api.wave.com/v1/checkout/sessions',{method:'POST',headers:{Authorization:`Bearer ${WAVE_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const data=await wr.json().catch(()=>({}));
    if(!wr.ok) return res.status(502).json({error:'Creation du paiement impossible'});
    db.prepare('UPDATE orders SET wave_checkout_id=? WHERE id=?').run(data.id,order.id);
    res.status(201).json({checkoutId:data.id,checkoutUrl:data.wave_launch_url});
  } catch(e){console.error(e);res.status(500).json({error:'Erreur serveur'});}
});

app.get('/api/orders/:id',(req,res)=>{const o=db.prepare('SELECT id,status,total_xof,wave_transaction_id,created_at FROM orders WHERE id=?').get(Number(req.params.id)); o?res.json(o):res.status(404).json({error:'Introuvable'});});
app.get('/paiement/succes',(_req,res)=>res.send('Paiement transmis. JULKO STORE verifie la confirmation Wave.'));
app.get('/paiement/erreur',(_req,res)=>res.status(400).send('Le paiement Wave n a pas abouti.'));

function verifyWaveSignature(rawBody,header,secret){const parts=header.split(',').map(x=>x.trim());const t=parts.find(x=>x.startsWith('t='))?.slice(2);const sigs=parts.filter(x=>x.startsWith('v1=')).map(x=>x.slice(3));if(!t||!sigs.length)return false;const ts=Number(t),now=Math.floor(Date.now()/1000);if(!Number.isFinite(ts)||Math.abs(now-ts)>300)return false;const expected=crypto.createHmac('sha256',secret).update(t+rawBody).digest('hex');return sigs.some(s=>s.length===expected.length&&crypto.timingSafeEqual(Buffer.from(s),Buffer.from(expected)));}
app.listen(PORT,()=>console.log(`JULKO STORE backend: ${PORT}`));
