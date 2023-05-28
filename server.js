// Import des modules
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');

// Configuration de Sequelize pour se connecter à la base de données
const sequelize = new Sequelize('meetzic', 'root', '', {
  host: 'localhost',
  dialect: 'mysql',
});

// Définition du modèle User
const User = sequelize.define('User', {
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  role: {
    type: DataTypes.STRING,
    allowNull: false,
    defaultValue: 'user',
  },
});

// Initialisation d'Express
const app = express();
app.use(bodyParser.json());

// Route d'inscription
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    // Vérifier si l'utilisateur existe déjà
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'L\'utilisateur existe déjà' });
    }
    
    // Hasher le mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Créer un nouvel utilisateur
    const newUser = await User.create({ email, password: hashedPassword });
    
    // Générer un token JWT pour l'utilisateur
    const token = jwt.sign({ userId: newUser.id, role: newUser.role }, 'secret_key');
    
    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Une erreur est survenue lors de l\'inscription' });
  }
});

// Route de connexion
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    // Vérifier si l'utilisateur existe
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'L\'utilisateur n\'existe pas' });
    }
    
    // Vérifier le mot de passe
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Mot de passe incorrect' });
    }
    
    // Générer un token JWT pour l'utilisateur
    const token = jwt.sign({ userId: user.id, role: user.role }, 'secret_key');
    
    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Une erreur est survenue lors de la connexion' });
  }
});

// Middleware pour vérifier l'authentification de l'utilisateur
function authenticateUser(req, res, next) {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ error: 'Accès non autorisé' });
  }
  
  jwt.verify(token, 'secret_key', (err, decodedToken) => {
    if (err) {
      return res.status(401).json({ error: 'Accès non autorisé' });
    }
    
    req.userId = decodedToken.userId;
    req.role = decodedToken.role;
    next();
  });
}

// Route protégée accessible uniquement par l'administrateur
app.get('/admin', authenticateUser, (req, res) => {
  if (req.role !== 'admin') {
    return res.status(403).json({ error: 'Accès interdit' });
  }
  
  res.json({ message: 'Bienvenue, administrateur' });
});

app.use(express.static('client/build'));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
});

// Démarrer le serveur
app.listen(3000, () => {
  console.log('Serveur démarré sur le port 3000');
});
