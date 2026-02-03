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
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, // Обязательно true для 465
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    debug: true, // Включает детальный вывод в логи
    logger: true, // Выводит каждый шаг SMTP-команд в консоль Render
    tls: {
        rejectUnauthorized: false
    },
    connectionTimeout: 20000, // Увеличиваем до 20 секунд
    greetingTimeout: 20000,
    socketTimeout: 20000
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
    const { email } = req.body;
    console.log("ПОПЫТКА СБРОСА ДЛЯ:", email);

    try {
        const token = Math.random().toString(36).substring(2, 15);

        // 1. Обновление базы
        const { data, error: dbError } = await supabase
            .from('users')
            .update({ reset_token: token })
            .eq('email', email)
            .select();

        if (dbError) throw new Error("DB_ERROR: " + dbError.message);
        if (!data || data.length === 0) return res.status(404).json({ error: "EMAIL_NOT_FOUND" });

        console.log("БАЗА ОБНОВЛЕНА, ТОКЕН:", token);

        // 2. Отправка почты (используем промис вместо колбэка)
        const resetLink = `${process.env.SITE_URL}/reset-password.html?token=${token}`;
        
        await transporter.sendMail({
            from: `"EVVI Support" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Восстановление пароля',
            html: `Ссылка для сброса: <a href="${resetLink}">${resetLink}</a>`
        });

        console.log("ПИСЬМО ОТПРАВЛЕНО УСПЕШНО");
        res.json({ success: true, message: "Инструкция отправлена!" });

    } catch (error) {
        // ЛЮБАЯ ошибка теперь ТОЧНО попадет в логи
        console.error("КРИТИЧЕСКАЯ ОШИБКА В API:");
        console.error(error.message); 
        res.status(500).json({ error: error.message });
    }
});

// Сохранение нового пароля
app.post('/api/forgot-password', async (req, res) => {
    console.log(">>> [LOG]: Получен запрос на сброс для:", req.body.email);
    
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: "Email не указан" });

        const token = Math.random().toString(36).substring(2, 15);

        // 1. Пробуем обновить Supabase
        console.log(">>> [LOG]: Обновляю токен в Supabase...");
        const { data, error: dbError } = await supabase
            .from('users')
            .update({ reset_token: token })
            .eq('email', email)
            .select();

        if (dbError) {
            console.error(">>> [ERR] Ошибка Supabase:", dbError.message);
            return res.status(500).json({ error: "Ошибка БД: " + dbError.message });
        }

        if (!data || data.length === 0) {
            console.warn(">>> [WARN]: Email не найден в базе данных");
            return res.status(404).json({ error: "Пользователь не найден" });
        }

        // 2. Настройка ссылки (SITE_URL из Render или авто-определение)
        const baseUrl = process.env.SITE_URL ? process.env.SITE_URL.replace(/\/$/, "") : `https://${req.get('host')}`;
        const resetLink = `${baseUrl}/reset-password.html?token=${token}`;
        console.log(">>> [LOG]: Ссылка сформирована:", resetLink);

        // 3. Отправка почты
        const mailOptions = {
            from: `"CyberNet Support" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'CyberNet | Восстановление доступа',
            html: `
                <div style="background:#000; color:#0ac2fa; padding:20px; border:1px solid #0ac2fa;">
                    <h2>СБРОС ПАРОЛЯ</h2>
                    <p>Для установки нового пароля нажмите на ссылку:</p>
                    <a href="${resetLink}" style="color:#fff;">${resetLink}</a>
                </div>`
        };

        console.log(">>> [LOG]: Начинаю отправку через Nodemailer...");
        transporter.sendMail(mailOptions, (mailErr, info) => {
            if (mailErr) {
                console.error(">>> [ERR] Ошибка Nodemailer:", mailErr.message);
                return res.status(500).json({ error: "Ошибка почты: " + mailErr.message });
            }
            console.log(">>> [LOG]: Письмо успешно ушло!", info.response);
            return res.json({ message: "Инструкция отправлена на Email" });
        });

    } catch (err) {
        console.error(">>> [CRITICAL]:", err);
        return res.status(500).json({ error: "Критический сбой сервера" });
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
    res.sendFile(path.join(__dirname, 'main.html'));
});

// 6. ЗАПУСК
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    console.log(`--- SYSTEM ONLINE | PORT: ${PORT} ---`);
});

process.on('SIGTERM', () => {
    server.close(() => console.log('Process terminated'));
});