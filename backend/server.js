import express from 'express';
import mysql from 'mysql';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';


// const express = require('express');
// const router = express.Router();

// // Middleware d'authentification admin (à implémenter selon vos besoins)
// const requireAdmin = (req, res, next) => {
//   // Vérifier si l'utilisateur est un admin
//   if (!req.user?.isAdmin) {
//     return res.status(403).json({ error: 'Accès non autorisé' });
//   }
//   next();
// };

// // Route pour obtenir les statistiques
// router.get('/api/admin/stats', requireAdmin, (req, res) => {
//   const stats = {
//     total: comments.length,
//     pending: comments.filter(c => c.status === 'pending').length,
//     responded: comments.filter(c => c.status === 'responded').length,
//     archived: comments.filter(c => c.status === 'archived').length
//   };
  
//   res.json(stats);
// });

// // Route pour archiver un commentaire
// router.post('/api/admin/comments/:id/archive', requireAdmin, (req, res) => {
//   const { id } = req.params;
//   const comment = comments.find(c => c.id === parseInt(id));
  
//   if (!comment) {
//     return res.status(404).json({ error: 'Commentaire non trouvé' });
//   }
  
//   comment.status = 'archived';
//   comment.archivedAt = new Date();
  
//   res.json(comment);
// });

// // Route pour mettre à jour le statut d'un commentaire
// router.patch('/api/admin/comments/:id/status', requireAdmin, (req, res) => {
//   const { id } = req.params;
//   const { status } = req.body;
  
//   const comment = comments.find(c => c.id === parseInt(id));
//   if (!comment) {
//     return res.status(404).json({ error: 'Commentaire non trouvé' });
//   }
  
//   // Vérifier que le statut est valide
//   if (!['pending', 'responded', 'archived'].includes(status)) {
//     return res.status(400).json({ error: 'Statut invalide' });
//   }
  
//   comment.status = status;
//   comment.updatedAt = new Date();
  
//   res.json(comment);
// });

// // Route pour supprimer un commentaire (soft delete)
// router.delete('/api/admin/comments/:id', requireAdmin, (req, res) => {
//   const { id } = req.params;
//   const commentIndex = comments.findIndex(c => c.id === parseInt(id));
  
//   if (commentIndex === -1) {
//     return res.status(404).json({ error: 'Commentaire non trouvé' });
//   }
  
//   // Marquer comme supprimé au lieu de supprimer réellement
//   comments[commentIndex].deleted = true;
//   comments[commentIndex].deletedAt = new Date();
  
//   res.status(204).send();
// });

// module.exports = router;



const app = express();

// Middleware - Suppression des doublons et ajout de bodyParser correctement
app.use(cors());
app.use(express.json({ limit: '16mb' }));
app.use(bodyParser.json({ limit: '16mb' }));
app.use(bodyParser.urlencoded({ limit: '16mb', extended: true }));

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'dbobf'
});

connection.connect((err) => {
    if (err) {
        console.error('Erreur de connexion à la base de données:', err);
        return;
    }
    console.log('Connecté à la base de données MySQL');
});

// Middleware de vérification du token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(403).send('Un token est requis pour l\'authentification');
    }
    
    try {
        const decoded = jwt.verify(token, 'votre_clé_secrète');
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).send('Token invalide');
    }
};

// Route pour l'inscription
app.post('/signup', async (req, res) => {
    const { email, password, role = 'user' } = req.body;

    try {
        connection.query('SELECT * FROM users WHERE email = ?', [email], async (error, results) => {
            if (error) {
                console.error('Erreur:', error);
                return res.status(500).json({ error: 'Erreur lors de la vérification de l\'utilisateur.' });
            }
            
            if (results.length > 0) {
                return res.status(409).json({ error: 'Cet email est déjà utilisé.' });
            }

            // Hachage du mot de passe
            const hashedPassword = await bcrypt.hash(password, 10);
            const createdAt = new Date();

            // Insertion de l'utilisateur
            connection.query(
                'INSERT INTO users (email, password, role, created_at) VALUES (?, ?, ?, ?)',
                [email, hashedPassword, role, createdAt],
                (err, result) => {
                    if (err) {
                        console.error('Erreur:', err);
                        return res.status(500).json({ error: 'Erreur lors de l\'inscription.' });
                    }

                    // Création du token
                    const token = jwt.sign(
                        { userId: result.insertId, role: role },
                        'votre_clé_secrète',
                        { expiresIn: '24h' }
                    );

                    res.status(201).json({
                        message: 'Utilisateur créé avec succès',
                        token,
                        user: {
                            id: result.insertId,
                            email,
                            role
                        }
                    });
                }
            );
        });
    } catch (error) {
        console.error('Erreur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Route pour la connexion
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        connection.query('SELECT * FROM users WHERE email = ?', [email], async (error, results) => {
            if (error) {
                return res.status(500).json({ error: 'Erreur lors de la connexion.' });
            }

            if (results.length === 0) {
                return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
            }

            const user = results[0];
            const validPassword = await bcrypt.compare(password, user.password);

            if (!validPassword) {
                return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
            }

            const token = jwt.sign(
                { userId: user.id, role: user.role },
                'votre_clé_secrète',
                { expiresIn: '24h' }
            );

            res.json({
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    role: user.role
                }
            });
        });
    } catch (error) {
        console.error('Erreur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Route pour afficher toutes les actualités
app.get('/afficheActu', (req, res) => {
    const query = `
        SELECT 
            id_act,
            titre,
            details,
            DATE_FORMAT(date_act, '%Y-%m-%d') as date_act,
            image,
            mime_type
        FROM actualites 
        ORDER BY date_act DESC
    `;

    connection.query(query, (err, results) => {
        if (err) {
            console.error('Erreur lors de la récupération des actualités:', err);
            res.status(500).json({ error: 'Erreur serveur' });
            return;
        }

        const formattedResults = results.map(item => ({
            id_act: item.id_act,
            titre: item.titre,
            details: item.details,
            date_act: item.date_act,
            image: item.image ? `data:${item.mime_type};base64,${item.image.toString('base64')}` : null
        }));

        res.json(formattedResults);
    });
});

// Route pour ajouter une actualité
app.post('/ajoutActu', (req, res) => {
    const { titre, details, date, image, mimeType } = req.body;

    let imageBuffer = null;
    if (image) {
        // Extraire la partie base64 de la chaîne data URL
        const base64Data = image.split(';base64,').pop();
        imageBuffer = Buffer.from(base64Data, 'base64');
    }

    const query = 'INSERT INTO actualites (titre, details, date_act, image, mime_type) VALUES (?, ?, ?, ?, ?)';
    const values = [titre, details, date, imageBuffer, mimeType];

    connection.query(query, values, (err, result) => {
        if (err) {
            console.error('Erreur lors de l\'ajout de l\'actualité:', err);
            return res.status(500).json({ error: 'Erreur serveur' });
        }
        res.json({
            message: 'Actualité ajoutée avec succès',
            id: result.insertId
        });
    });
});

// Route pour supprimer une actualité
app.delete('/api/delete-news/:id', (req, res) => {
    const id = req.params.id;
    
    const query = 'DELETE FROM actualites WHERE id_act = ?';
    
    connection.query(query, [id], (err, result) => {
        if (err) {
            console.error('Erreur lors de la suppression de l\'actualité:', err);
            res.status(500).json({ error: 'Erreur serveur' });
            return;
        }
        
        if (result.affectedRows === 0) {
            res.status(404).json({ error: 'Actualité non trouvée' });
            return;
        }
        
        res.json({ message: 'Actualité supprimée avec succès' });
    });
});

const PORT = process.env.PORT || 8081;
app.listen(PORT, () => {
    console.log(`Serveur démarré sur le port ${PORT}`);
});



