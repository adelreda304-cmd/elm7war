/*
=====================================================
 Elm7war – FULL SINGLE-FILE PRODUCTION APP
 Backend + Admin Panel UI + APIs
=====================================================
 Stack:
 - Node.js
 - Express
 - MongoDB (Mongoose)
 - JWT Auth
 - Admin Panel (HTML inside Express)
=====================================================
*/

import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// Recreate __dirname for ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ================== CONFIG ==================
dotenv.config();
const app = express();
app.use(express.json());

app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// ================== DATABASE ==================
mongoose.connect(process.env.MONGO_URI);

// ================== MODELS ==================
const AdminSchema = new mongoose.Schema({
    email: { type: String, unique: true },
    password: String
});
AdminSchema.pre('save', async function () {
    if (!this.isModified('password')) return;
    this.password = await bcrypt.hash(this.password, 10);
});
const Admin = mongoose.model('Admin', AdminSchema);

const Room = mongoose.model('Room', new mongoose.Schema({
    name: String,
    mode: String,
    startTime: Date,
    prize: String,
    isPaid: Boolean
}));

const Registration = mongoose.model('Registration', new mongoose.Schema({
    roomId: mongoose.Schema.Types.ObjectId,
    playerName: String,
    freeFireId: { type: String, unique: true },
    status: { type: String, default: 'pending' }
}));

const Result = mongoose.model('Result', new mongoose.Schema({
    roomId: mongoose.Schema.Types.ObjectId,
    winners: [String]
}));

// ================== AUTH MIDDLEWARE ==================
const adminAuth = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).send('No token');
    try {
        req.admin = jwt.verify(token.split(' ')[1], process.env.JWT_SECRET);
        next();
    } catch {
        res.status(401).send('Invalid token');
    }
};

// ================== ADMIN LOGIN ==================
app.post('/api/admin/login', async (req, res) => {
    // Vercel fix: Ensure admin exists on first login attempt
    if (!await Admin.findOne({ email: 'admin@elm7war.com' })) {
        await Admin.create({ email: 'admin@elm7war.com', password: 'ChangeMe123' });
    }

    const admin = await Admin.findOne({ email: req.body.email });
    if (!admin) return res.status(401).send('Invalid');

    const ok = await bcrypt.compare(req.body.password, admin.password);
    if (!ok) return res.status(401).send('Invalid');

    const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET);
    res.json({ token });
});

// ================== ROOMS CRUD ==================
app.post('/api/admin/rooms', adminAuth, async (req, res) => {
    res.json(await Room.create(req.body));
});
app.get('/api/admin/rooms', adminAuth, async (req, res) => {
    res.json(await Room.find());
});
app.get('/api/rooms', async (req, res) => {
    res.json(await Room.find());
});
app.delete('/api/admin/rooms/:id', adminAuth, async (req, res) => {
    await Room.findByIdAndDelete(req.params.id);
    res.send('Deleted');
});


// ================== REGISTRATIONS ==================
app.post('/api/register', async (req, res) => {
    res.json(await Registration.create(req.body));
});
app.get('/api/admin/registrations', adminAuth, async (req, res) => {
    res.json(await Registration.find());
});
app.post('/api/admin/registrations/:id/approve', adminAuth, async (req, res) => {
    res.json(await Registration.findByIdAndUpdate(req.params.id, { status: 'approved' }));
});

// ================== RESULTS ==================
app.post('/api/admin/results', adminAuth, async (req, res) => {
    res.json(await Result.create(req.body));
});
app.get('/api/results', async (req, res) => {
    res.json(await Result.find().sort({ _id: -1 }));
});

// ================== LEADERBOARD & PROFILE ==================
app.get('/api/leaderboard', async (req, res) => {
    const results = await Result.find();
    const tally = {};
    results.forEach(r => {
        r.winners.forEach(w => {
            const name = w.trim();
            if (name) tally[name] = (tally[name] || 0) + 1;
        });
    });

    // Convert to array and sort
    const leaderboard = Object.entries(tally)
        .map(([name, wins]) => ({ name, wins }))
        .sort((a, b) => b.wins - a.wins)
        .slice(0, 10); // Top 10

    res.json(leaderboard);
});

app.get('/api/profile/:id', async (req, res) => {
    const query = req.params.id;
    // Search by FreeFire ID (exact) or Name (partial/exact)
    // We strictly search Registrations for history
    const history = await Registration.find({
        $or: [
            { freeFireId: query },
            { playerName: query }
        ]
    }).sort({ _id: -1 });

    res.json(history);
});

// ================== ADMIN UI ==================
app.use(express.static(path.join(__dirname, 'public')));

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ================== START ==================
// Vercel requires exporting the app
if (process.env.NODE_ENV !== 'production') {
    app.listen(process.env.PORT || 5000, async () => {
        if (!await Admin.findOne({ email: 'admin@elm7war.com' })) {
            await Admin.create({ email: 'admin@elm7war.com', password: 'ChangeMe123' });
        }
        console.log('Elm7war running');
    });
}

export default app;
