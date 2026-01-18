require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const compression = require('compression'); // Полезно для ускорения загрузки на Render

const app = express();

// 1. ИНИЦИАЛИЗАЦИЯ SUPABASE
// Проверка наличия переменных (чтобы сервер не упал без объяснения причин)
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_KEY) {
    console.error("CRITICAL ERROR: Supabase credentials missing in Environment Variables!");
    process.exit(1);
}
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// 2. НАСТРОЙКИ ДЛЯ RENDER
app.use(compression()); // Сжимает файлы для быстрой отдачи через мобильный интернет
app.use(express.json());
app.use(express.static(path.join(__dirname))); 

// Настройка сессий (Render часто перезагружает инстансы, поэтому secret важен)
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-cyber-key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // true только если у тебя HTTPS (на Render по умолчанию так, но для начала оставим false)
        maxAge: 24 * 60 * 60 * 1000 // 24 часа
    }
}));

// 3. ЭНДПОИНТЫ (API)
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (password.length < 8) return res.status(400).json({ error: "SHORT_PASSWORD" });

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

app.get('/api/status', (req, res) => {
    res.json(req.session.username ? { loggedIn: true, username: req.session.username } : { loggedIn: false });
});

app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.status(200).send('Logged out');
});

// 4. ГЛАВНЫЙ МАРШРУТ (Важно для Render)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'main.html'));
});

// 5. ЗАПУСК СЕРВЕРА
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    console.log(`--- SYSTEM ONLINE ---`);
    console.log(`PORT: ${PORT}`);
    console.log(`DATABASE: Supabase Cloud`);
});

// 6. ОБРАБОТКА СИГНАЛОВ ЗАВЕРШЕНИЯ (Для "мягкой" перезагрузки на Render)
process.on('SIGTERM', () => {
    server.close(() => {
        console.log('Process terminated: Closing server...');
    });
});