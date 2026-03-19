// server.js
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const mysql = require('mysql2/promise');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();

// Trust proxy (Hostinger ke liye)
app.set('trust proxy', 1);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'iiuiJournalSecretKey2026',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Database connection
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'iiui_journal',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Email transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
};

// Create uploads directory
const uploadDir = path.join(__dirname, 'public/uploads/past-papers');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, 'paper-' + uniqueSuffix + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only images are allowed'));
        }
    }
});

// ============ ROUTES ============

// Welcome page
app.get('/', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/home');
    }
    res.render('welcome');
});

// Login
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const [users] = await pool.execute(
            'SELECT * FROM users WHERE email = ? AND is_verified = TRUE',
            [email]
        );
        
        if (users.length === 0) {
            return res.render('login', { error: 'Invalid email or password' });
        }
        
        const user = users[0];
        const valid = await bcrypt.compare(password, user.password_hash);
        
        if (!valid) {
            return res.render('login', { error: 'Invalid email or password' });
        }
        
        req.session.userId = user.id;
        req.session.userEmail = user.email;
        res.redirect('/home');
    } catch (error) {
        console.error('Login error:', error);
        res.render('login', { error: 'Login failed' });
    }
});

// Signup
app.get('/signup', (req, res) => {
    res.render('signup', { error: null });
});

app.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email.endsWith('@iiu.edu.pk') && !email.endsWith('@student.iiu.edu.pk')) {
        return res.render('signup', { error: 'Only IIUI email addresses allowed' });
    }
    
    if (password.length < 6) {
        return res.render('signup', { error: 'Password must be at least 6 characters' });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const token = crypto.randomBytes(32).toString('hex');
        
        await pool.execute(
            'INSERT INTO users (email, password_hash, verification_token) VALUES (?, ?, ?)',
            [email, hashedPassword, token]
        );
        
        const baseUrl = process.env.NODE_ENV === 'production' 
            ? 'https://iiuijournal.com'
            : 'http://localhost:5050';
        
        const verificationLink = `${baseUrl}/verify/${token}`;
        
        await transporter.sendMail({
            to: email,
            subject: 'Verify your IIUI Journal account',
            text: `Click this link to verify your email: ${verificationLink}`
        });
        
        res.render('login', { error: 'Verification email sent. Please check your inbox.' });
    } catch (error) {
        console.error('Signup error:', error);
        if (error.code === 'ER_DUP_ENTRY') {
            res.render('signup', { error: 'Email already registered' });
        } else {
            res.render('signup', { error: 'Signup failed' });
        }
    }
});

// Email verification
app.get('/verify/:token', async (req, res) => {
    try {
        const [result] = await pool.execute(
            'UPDATE users SET is_verified = TRUE WHERE verification_token = ?',
            [req.params.token]
        );
        
        if (result.affectedRows > 0) {
            res.render('login', { error: 'Email verified! You can now login.' });
        } else {
            res.render('login', { error: 'Invalid verification link' });
        }
    } catch (error) {
        console.error('Verification error:', error);
        res.render('login', { error: 'Verification failed' });
    }
});

// Home
app.get('/home', requireAuth, async (req, res) => {
    try {
        const [posts] = await pool.execute(`
            SELECT p.*, u.email 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            ORDER BY p.created_at DESC
        `);
        
        res.render('home', { 
            posts,
            userEmail: req.session.userEmail 
        });
    } catch (error) {
        console.error('Home error:', error);
        res.redirect('/login');
    }
});

// New Post
app.get('/post/new', requireAuth, (req, res) => {
    res.render('new-post', { error: null });
});

app.post('/post/new', requireAuth, async (req, res) => {
    const { title, description, category } = req.body;
    
    if (!title || !description || !category) {
        return res.render('new-post', { error: 'All fields are required' });
    }
    
    try {
        await pool.execute(
            'INSERT INTO posts (user_id, title, description, category) VALUES (?, ?, ?, ?)',
            [req.session.userId, title, description, category]
        );
        
        res.redirect('/home');
    } catch (error) {
        console.error('Post error:', error);
        res.render('new-post', { error: 'Failed to create post' });
    }
});

// Post Detail
app.get('/post/:id', requireAuth, async (req, res) => {
    try {
        const [posts] = await pool.execute(`
            SELECT p.*, u.email 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            WHERE p.id = ?
        `, [req.params.id]);
        
        if (posts.length === 0) {
            return res.redirect('/home');
        }
        
        const [replies] = await pool.execute(`
            SELECT r.*, u.email 
            FROM replies r 
            JOIN users u ON r.user_id = u.id 
            WHERE r.post_id = ? 
            ORDER BY r.created_at ASC
        `, [req.params.id]);
        
        res.render('post-detail', {
            post: posts[0],
            replies,
            userId: req.session.userId,
            error: null
        });
    } catch (error) {
        console.error('Post detail error:', error);
        res.redirect('/home');
    }
});

// Reply to Post
app.post('/post/:id/reply', requireAuth, async (req, res) => {
    const { content } = req.body;
    
    if (!content) {
        return res.redirect(`/post/${req.params.id}`);
    }
    
    try {
        await pool.execute(
            'INSERT INTO replies (post_id, user_id, content) VALUES (?, ?, ?)',
            [req.params.id, req.session.userId, content]
        );
        
        res.redirect(`/post/${req.params.id}`);
    } catch (error) {
        console.error('Reply error:', error);
        res.redirect(`/post/${req.params.id}`);
    }
});

// Resolve Post
app.post('/post/:id/resolve', requireAuth, async (req, res) => {
    try {
        const [posts] = await pool.execute(
            'SELECT user_id FROM posts WHERE id = ?',
            [req.params.id]
        );
        
        if (posts.length > 0 && posts[0].user_id === req.session.userId) {
            await pool.execute(
                'UPDATE posts SET status = "Resolved" WHERE id = ?',
                [req.params.id]
            );
        }
        
        res.redirect(`/post/${req.params.id}`);
    } catch (error) {
        console.error('Resolve error:', error);
        res.redirect(`/post/${req.params.id}`);
    }
});

// Announcements
app.get('/announcements', requireAuth, async (req, res) => {
    try {
        const [announcements] = await pool.execute(`
            SELECT a.*, u.email 
            FROM announcements a 
            JOIN users u ON a.user_id = u.id 
            ORDER BY a.created_at DESC
        `);
        
        res.render('announcements', { 
            announcements,
            userEmail: req.session.userEmail,
            userId: req.session.userId
        });
    } catch (error) {
        console.error('Announcements error:', error);
        res.redirect('/home');
    }
});

app.get('/announcements/new', requireAuth, (req, res) => {
    res.render('new-announcement', { error: null });
});

app.post('/announcements/new', requireAuth, upload.single('announcement_image'), async (req, res) => {
    const { title, content } = req.body;
    
    if (!title || !content) {
        return res.render('new-announcement', { 
            error: 'Title and content are required' 
        });
    }
    
    try {
        let imagePath = null;
        if (req.file) {
            imagePath = '/uploads/past-papers/' + req.file.filename;
        }
        
        await pool.execute(
            'INSERT INTO announcements (user_id, title, content, image_path) VALUES (?, ?, ?, ?)',
            [req.session.userId, title, content, imagePath]
        );
        
        res.redirect('/announcements');
    } catch (error) {
        console.error('Announcement create error:', error);
        res.render('new-announcement', { error: 'Failed to create announcement' });
    }
});

app.post('/announcements/delete/:id', requireAuth, async (req, res) => {
    try {
        const [announcements] = await pool.execute(
            'SELECT user_id FROM announcements WHERE id = ?',
            [req.params.id]
        );
        
        if (announcements.length > 0 && announcements[0].user_id === req.session.userId) {
            const [announcement] = await pool.execute(
                'SELECT image_path FROM announcements WHERE id = ?',
                [req.params.id]
            );
            
            if (announcement[0].image_path) {
                const filePath = path.join(__dirname, 'public', announcement[0].image_path);
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                }
            }
            
            await pool.execute('DELETE FROM announcements WHERE id = ?', [req.params.id]);
        }
        
        res.redirect('/announcements');
    } catch (error) {
        console.error('Delete error:', error);
        res.redirect('/announcements');
    }
});

// Blogs
app.get('/blogs', requireAuth, async (req, res) => {
    try {
        const [blogs] = await pool.execute(`
            SELECT b.*, u.email 
            FROM blogs b 
            JOIN users u ON b.user_id = u.id 
            ORDER BY b.created_at DESC
        `);
        
        res.render('blogs', { blogs });
    } catch (error) {
        console.error('Blogs error:', error);
        res.redirect('/home');
    }
});

app.get('/blog/new', requireAuth, (req, res) => {
    res.render('new-blog', { error: null });
});

app.post('/blog/new', requireAuth, async (req, res) => {
    const { title, content } = req.body;
    
    if (!title || !content) {
        return res.render('new-blog', { error: 'All fields are required' });
    }
    
    try {
        await pool.execute(
            'INSERT INTO blogs (user_id, title, content) VALUES (?, ?, ?)',
            [req.session.userId, title, content]
        );
        
        res.redirect('/blogs');
    } catch (error) {
        console.error('Blog create error:', error);
        res.render('new-blog', { error: 'Failed to create blog' });
    }
});

// Past Papers
app.get('/past-papers', requireAuth, async (req, res) => {
    try {
        const [papers] = await pool.execute(`
            SELECT p.*, u.email 
            FROM past_papers p 
            JOIN users u ON p.user_id = u.id 
            ORDER BY p.created_at DESC
        `);
        
        res.render('past-papers', { 
            papers,
            userEmail: req.session.userEmail 
        });
    } catch (error) {
        console.error('Past papers error:', error);
        res.redirect('/home');
    }
});

app.get('/past-papers/upload', requireAuth, (req, res) => {
    res.render('upload-paper', { error: null });
});

app.post('/past-papers/upload', requireAuth, upload.single('paper_image'), async (req, res) => {
    const { title, description, department } = req.body;
    
    if (!title || !department || !req.file) {
        return res.render('upload-paper', { 
            error: 'Title, department, and image are required' 
        });
    }
    
    try {
        const imagePath = '/uploads/past-papers/' + req.file.filename;
        
        await pool.execute(
            'INSERT INTO past_papers (user_id, title, description, department, image_path) VALUES (?, ?, ?, ?, ?)',
            [req.session.userId, title, description, department, imagePath]
        );
        
        res.redirect('/past-papers');
    } catch (error) {
        console.error('Upload error:', error);
        res.render('upload-paper', { error: 'Failed to upload paper' });
    }
});

// About
app.get('/about', (req, res) => {
    res.render('about', { 
        userEmail: req.session.userEmail || null 
    });
});

// Contact
app.get('/contact', (req, res) => {
    res.render('contact', { 
        userEmail: req.session.userEmail || null,
        error: null,
        success: null 
    });
});

app.post('/contact', async (req, res) => {
    const { name, email, subject, message } = req.body;
    
    if (!name || !email || !subject || !message) {
        return res.render('contact', { 
            userEmail: req.session.userEmail || null,
            error: 'All fields are required',
            success: null 
        });
    }
    
    try {
        await pool.execute(
            'INSERT INTO contact_messages (name, email, subject, message) VALUES (?, ?, ?, ?)',
            [name, email, subject, message]
        );
        
        res.render('contact', { 
            userEmail: req.session.userEmail || null,
            error: null,
            success: 'Your message has been sent. We will get back to you soon.' 
        });
    } catch (error) {
        console.error('Contact error:', error);
        res.render('contact', { 
            userEmail: req.session.userEmail || null,
            error: 'Failed to send message. Please try again.',
            success: null 
        });
    }
});

// Privacy
app.get('/privacy', (req, res) => {
    res.render('privacy', { 
        userEmail: req.session.userEmail || null 
    });
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log('Logout error:', err);
        }
        res.redirect('/');
    });
});

// ============ START SERVER ============
const PORT = process.env.PORT || 5050;

app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
    console.log(`🌐 Visit: http://localhost:${PORT}`);
});