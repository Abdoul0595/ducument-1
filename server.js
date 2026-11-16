// server.js — API REST Express + stockage JSON (démo, à remplacer par une vraie base en production)
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DB_FILE = path.join(__dirname, 'data', 'db.json');
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Utilitaires ----------
// Mots de passe hachés avec scrypt (intégré à Node.js, jamais stockés en clair)
const hashPassword = (pwd, salt = crypto.randomBytes(16).toString('hex')) =>
  ({ salt, hash: crypto.scryptSync(String(pwd), salt, 64).toString('hex') });
const checkPassword = (pwd, user) => hashPassword(pwd, user.salt).hash === user.hash;

const read = () => JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
const write = db => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
const nextId = list => Math.max(0, ...list.map(x => x.id)) + 1;
const publicUser = u => ({ id: u.id, name: u.name, email: u.email, role: u.role });
const withRating = p => ({
  ...p,
  rating: p.reviews.length
    ? +(p.reviews.reduce((s, r) => s + r.rating, 0) / p.reviews.length).toFixed(1)
    : 0
});
// Ne garde que les champs modifiables d'un produit (protection contre l'injection de champs)
const pickProduct = b => ({
  name: String(b.name), category: b.category, price: +b.price, stock: +b.stock,
  image: b.image || '', description: b.description || '', featured: !!b.featured
});

// ---------- Données de démonstration (premier lancement) ----------
if (!fs.existsSync(DB_FILE)) {
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  const img = t => `https://placehold.co/600x450?text=${encodeURIComponent(t)}`;
  const product = (id, name, category, price, stock, featured, description, reviews = []) =>
    ({ id, name, category, price, stock, featured, image: img(name), description, reviews });
  write({
    users: [{ id: 1, name: 'Admin', email: 'admin@shop.fr', role: 'admin', ...hashPassword('admin123') }],
    sessions: {},
    orders: [],
    products: [
      product(1, 'Perceuse-visseuse 18V', 'outils-electriques', 89.9, 12, true,
        'Batterie Li-ion 2 Ah, deux vitesses, 25 accessoires inclus.',
        [{ user: 'Koffi', rating: 5, comment: 'Puissante et légère.' }]),
      product(2, 'Scie circulaire 1400 W', 'outils-electriques', 129, 5, true,
        'Profondeur de coupe 65 mm, guide laser intégré.',
        [{ user: 'Awa', rating: 4, comment: 'Bonne précision de coupe.' }]),
      product(3, 'Jeu de tournevis (12 pièces)', 'outils-manuels', 24.5, 40, false,
        'Embouts magnétiques et manches ergonomiques.',
        [{ user: 'Yao', rating: 5, comment: 'Solides, très pratiques.' }]),
      product(4, 'Pince multiprise 250 mm', 'outils-manuels', 18.9, 25, true,
        'Acier chrome-vanadium, mâchoires réglables.'),
      product(5, 'Sécateur de jardin', 'jardinage', 15.5, 30, false,
        'Lame en acier trempé, ressort anti-blocage.',
        [{ user: 'Ama', rating: 3, comment: 'Correct pour un usage léger.' }]),
      product(6, 'Coffret de mèches à bois', 'accessoires', 12, 60, false,
        'Mèches de 3 à 10 mm, coffret de rangement.')
    ]
  });
}

// ---------- Authentification ----------
const requireAuth = (req, res, next) => {
  const db = read();
  const uid = db.sessions[(req.headers.authorization || '').replace('Bearer ', '')];
  req.user = db.users.find(u => u.id === uid);
  return req.user ? next() : res.status(401).json({ error: 'Connexion requise' });
};
const requireAdmin = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Accès administrateur requis' });

app.post('/api/auth/inscription', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 6)
    return res.status(400).json({ error: 'Champs requis ; mot de passe de 6 caractères minimum' });
  const db = read();
  if (db.users.some(u => u.email === email)) return res.status(409).json({ error: 'Email déjà utilisé' });
  const user = { id: nextId(db.users), name, email, role: 'client', ...hashPassword(password) };
  db.users.push(user);
  const token = crypto.randomBytes(24).toString('hex');
  db.sessions[token] = user.id;
  write(db);
  res.status(201).json({ token, user: publicUser(user) });
});

app.post('/api/auth/connexion', (req, res) => {
  const { email, password } = req.body;
  const db = read();
  const user = db.users.find(u => u.email === email);
  if (!user || !checkPassword(password || '', user))
    return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = crypto.randomBytes(24).toString('hex');
  db.sessions[token] = user.id;
  write(db);
  res.json({ token, user: publicUser(user) });
});

// ---------- Produits : catalogue, recherche et filtres ----------
app.get('/api/products', (req, res) => {
  const { q = '', category = '', min = 0, max = 1e9, rating = 0, sort = '' } = req.query;
  const tri = {
    'prix-asc': (a, b) => a.price - b.price,
    'prix-desc': (a, b) => b.price - a.price,
    note: (a, b) => b.rating - a.rating
  };
  const list = read().products.map(withRating).filter(p =>
    p.name.toLowerCase().includes(q.toLowerCase()) &&
    (!category || p.category === category) &&
    p.price >= +min && p.price <= +max && p.rating >= +rating);
  if (tri[sort]) list.sort(tri[sort]);
  res.json(list);
});

app.get('/api/products/:id', (req, res) => {
  const p = read().products.find(x => x.id == req.params.id);
  if (!p) return res.status(404).json({ error: 'Produit introuvable' });
  res.json(withRating(p));
});

app.post('/api/products/:id/avis', requireAuth, (req, res) => {
  const db = read();
  const p = db.products.find(x => x.id == req.params.id);
  const rating = +req.body.rating;
  if (!p) return res.status(404).json({ error: 'Produit introuvable' });
  if (!(rating >= 1 && rating <= 5)) return res.status(400).json({ error: 'Note comprise entre 1 et 5' });
  p.reviews.push({ user: req.user.name, rating, comment: String(req.body.comment || '').slice(0, 500) });
  write(db);
  res.status(201).json(withRating(p));
});

// ---------- Administration : ajout, modification, suppression ----------
const adminOnly = [requireAuth, requireAdmin];

app.post('/api/admin/products', adminOnly, (req, res) => {
  const db = read();
  const p = { id: nextId(db.products), reviews: [], ...pickProduct(req.body) };
  db.products.push(p);
  write(db);
  res.status(201).json(p);
});

app.put('/api/admin/products/:id', adminOnly, (req, res) => {
  const db = read();
  const i = db.products.findIndex(x => x.id == req.params.id);
  if (i < 0) return res.status(404).json({ error: 'Produit introuvable' });
  db.products[i] = { ...db.products[i], ...pickProduct(req.body) };
  write(db);
  res.json(db.products[i]);
});

app.delete('/api/admin/products/:id', adminOnly, (req, res) => {
  const db = read();
  db.products = db.products.filter(x => x.id != req.params.id);
  write(db);
  res.json({ ok: true });
});

// ---------- Commandes (paiement simulé) ----------
app.post('/api/commandes', requireAuth, (req, res) => {
  const items = Array.isArray(req.body.items) ? req.body.items : [];
  const carte = String(req.body.paiement?.carte || '').replace(/\s/g, '');
  if (!/^\d{16}$/.test(carte))
    return res.status(402).json({ error: 'Paiement refusé (simulation : saisissez 16 chiffres)' });

  const db = read();
  // Les prix sont recalculés côté serveur : le client ne peut pas les falsifier
  const lignes = items.map(i => ({ p: db.products.find(x => x.id == i.id), qty: +i.qty }));
  if (!lignes.length || lignes.some(({ p, qty }) => !p || qty < 1 || p.stock < qty))
    return res.status(400).json({ error: 'Panier invalide ou stock insuffisant' });

  lignes.forEach(({ p, qty }) => (p.stock -= qty));
  const order = {
    id: nextId(db.orders),
    userId: req.user.id,
    date: new Date().toISOString(),
    statut: 'Payée (simulation)',
    adresse: req.body.adresse || {},
    lignes: lignes.map(({ p, qty }) => ({ id: p.id, name: p.name, price: p.price, qty })),
    total: +lignes.reduce((s, { p, qty }) => s + p.price * qty, 0).toFixed(2)
  };
  db.orders.push(order);
  write(db);
  res.status(201).json(order);
});

app.listen(process.env.PORT || 3000, () => console.log('OutilsPro : http://localhost:3000'));
