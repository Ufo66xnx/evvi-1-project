const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

const app = express();

// 1. ПОДКЛЮЧЕНИЕ БАЗЫ ДАННЫХ
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) console.error("Ошибка БД:", err.message);
    else console.log("База данных: OK");
});

// 2. НАСТРОЙКИ СЕРВЕРА
app.use(express.json());
app.use(express.static(path.join(__dirname))); 
app.use(session({
    secret: 'cyber-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 }
}));

// 3. СОЗДАНИЕ ТАБЛИЦЫ
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT,
    password TEXT
)`);

// 4. РЕГИСТРАЦИЯ
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(
            `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
            [username, email, hashedPassword],
            function(err) {
                if (err) return res.status(400).json({ error: "Ошибка: юзер существует" });
                res.json({ success: true });
            }
        );
    } catch (e) {
        res.status(500).json({ error: "Ошибка сервера" });
    }
});

// 5. АВТОРИЗАЦИЯ
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.status(401).json({ error: "Неверный логин" });

        const match = await bcrypt.compare(password, user.password);
        if (match) {
            req.session.username = user.username;
            res.json({ success: true, username: user.username });
        } else {
            res.status(401).json({ error: "Неверный пароль" });
        }
    });
});

// 6. СТАТУС И ВЫХОД
app.get('/api/status', (req, res) => {
    res.json(req.session.username ? { loggedIn: true, username: req.session.username } : { loggedIn: false });
});

app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});
// Маршрут для главной страницы
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'main.html')); 
});


const PORT = process.env.PORT || 3000; // Берем порт от Render или 3000 для локалки


app.listen(PORT, () => {
    console.log(S`erver is running on port ${PORT}`);
});
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // 1. Проверка длины пароля
        if (password.length < 8) {
            return res.status(400).json({ error: "Пароль должен быть не менее 8 символов" });
        }

        // 2. Запрет на Admin и User (регистронезависимо)
        const forbiddenWords = ['admin', 'user'];
        const isForbidden = forbiddenWords.some(word => username.toLowerCase().includes(word));
        
        if (isForbidden) {
            return res.status(400).json({ error: "Логин содержит запрещенные слова (Admin, User)" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
            [username, email, hashedPassword],
            function(err) {
                if (err) return res.status(400).json({ error: "Имя уже занято" });
                res.json({ success: true });
            }
        );
    } catch (e) {
        res.status(500).json({ error: "Ошибка сервера" });
    }
});


