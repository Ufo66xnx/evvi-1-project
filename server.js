require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const compression = require('compression');
const nodemailer = require('nodemailer');

const app = express();

// 1. ИНИЦИАЛИЗАЦИЯ SUPABASE
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_KEY) {
    console.error("CRITICAL ERROR: Supabase credentials missing!");
    process.exit(1);
}
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// 2. НАСТРОЙКИ ПОЧТЫ
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// 3. MIDDLEWARE
app.use(compression());
app.use(express.json());

// Отдаем статику (HTML, CSS, JS) из корня проекта
app.use(express.static(path.join(__dirname)));

app.use(session({
    secret: process.env.SESSION_SECRET || 'cyber-punk-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // На Render HTTPS, но для тестов оставим false
        maxAge: 24 * 60 * 60 * 1000 
    }
}));

// 4. ЭНДПОИНТЫ (API)

// Регистрация
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!password || password.length < 8) return res.status(400).json({ error: "SHORT_PASSWORD" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const { error } = await supabase
            .from('users')
            .insert([{ username, email, password: hashedPassword }]);

        if (error) {
            if (error.code === '23505') return res.status(400).json({ error: "USER_EXISTS" });
            throw error;
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "SERVER_ERROR" });
    }
});

// Логин
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('username', username)
            .single();

        if (error || !user) return res.status(401).json({ error: "AUTH_FAILED" });

        const match = await bcrypt.compare(password, user.password);
        if (match) {
            req.session.username = user.username;
            res.json({ success: true, username: user.username });
        } else {
            res.status(401).json({ error: "AUTH_FAILED" });
        }
    } catch (e) {
        res.status(500).json({ error: "SERVER_ERROR" });
    }
});

// --- ВОССТАНОВЛЕНИЕ ПАРОЛЯ ---

// Запрос ссылки
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const token = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

        const { data, error } = await supabase
            .from('users')
            .update({ reset_token: token })
            .eq('email', email)
            .select();

        if (error || !data || data.length === 0) {
            return res.status(404).json({ error: "Email не найден в базе" });
        }

        // Авто-определение URL сайта
        const host = process.env.SITE_URL || `https://${req.get('host')}`;
        const resetLink = `${host}/reset-password.html?token=${token}`;

        const mailOptions = {
            from: `"CyberNet Support" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Восстановление доступа | CyberNet',
            html: `
                <div style="background:#050a10; color:#0ac2fa; padding:30px; border:2px solid #0ac2fa; font-family:sans-serif;">
                    <h2 style="text-align:center;">RECOVERY SYSTEM</h2>
                    <p>Для сброса пароля перейдите по ссылке:</p>
                    <a href="${resetLink}" style="color:#0ac2fa; font-weight:bold;">${resetLink}</a>
                    <p style="margin-top:20px; font-size:10px; color:#555;">Если вы не запрашивали сброс, игнорируйте это письмо.</p>
                </div>`
        };

        transporter.sendMail(mailOptions, (err) => {
            if (err) return res.status(500).json({ error: "Ошибка почты" });
            res.json({ message: "Письмо отправлено!" });
        });
    } catch (e) {
        res.status(500).json({ error: "SERVER_ERROR" });
    }
});

// Сохранение нового пароля
app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        if (!token || !newPassword) return res.status(400).json({ error: "INVALID_DATA" });

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const { data, error } = await supabase
            .from('users')
            .update({ password: hashedPassword, reset_token: null })
            .eq('reset_token', token)
            .select();

        if (error || !data || data.length === 0) {
            return res.status(400).json({ error: "Ссылка недействительна или устарела" });
        }
        res.json({ message: "Пароль успешно изменен!" });
    } catch (e) {
        res.status(500).json({ error: "SERVER_ERROR" });
    }
});

// Статус сессии
app.get('/api/status', (req, res) => {
    res.json(req.session.username ? { loggedIn: true, username: req.session.username } : { loggedIn: false });
});

// Выход
app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.status(200).send('Logged out');
});

// 5. РОУТИНГ (ВАЖНО)
// Если запрошен путь, которого нет в API — отдаем index.html или auth.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'auth.html'));
});

// 6. ЗАПУСК
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    console.log(`--- SYSTEM ONLINE | PORT: ${PORT} ---`);
});

process.on('SIGTERM', () => {
    server.close(() => console.log('Process terminated'));
});