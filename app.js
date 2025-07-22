require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');

const app = express();
const users = [];

app.use(session({
secret: process.env.SESSION_SECRET || 'your_strong_secret_here',
resave: false,
saveUninitialized: false,
cookie: {
httpOnly: true,
secure: process.env.NODE_ENV === 'production',
maxAge: 1000 * 60 * 60 * 24
}
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
{ usernameField: 'email' },
(email, password, done) => {
const user = users.find(u => u.email === email);
if (!user) return done(null, false, { message: 'Користувача не знайдено' });

bcrypt.compare(password, user.password, (err, isValid) => {
if (err) return done(err);
if (!isValid) return done(null, false, { message: 'Невірний пароль' });
return done(null, user);
});
}
));

passport.serializeUser((user, done) => done(null, user.email));
passport.deserializeUser((email, done) => done(null, users.find(u => u.email === email)));

const styles = `
<style>
body {
font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
line-height: 1.6;
max-width: 800px;
margin: 0 auto;
padding: 20px;
color: #333;
background-color: #f5f5f5;
}
h1, h2 {
color: #2c3e50;
}
.container {
background: white;
padding: 30px;
border-radius: 8px;
box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}
form {
margin: 20px 0;
padding: 20px;
background: #f9f9f9;
border-radius: 5px;
}
input {
display: block;
width: 100%;
padding: 10px;
margin: 10px 0;
border: 1px solid #ddd;
border-radius: 4px;
box-sizing: border-box;
}
button {
background: #3498db;
color: white;
border: none;
padding: 10px 20px;
border-radius: 4px;
cursor: pointer;
font-size: 16px;
}
button:hover {
background: #2980b9;
}
.nav {
margin: 20px 0;
}
.nav a {
color: #3498db;
text-decoration: none;
}
.nav a:hover {
text-decoration: underline;
}
.error {
color: #e74c3c;
}
.success {
color: #27ae60;
}
</style>
`;

app.get('/', (req, res) => {
res.send(`
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Система автентифікації</title>
${styles}
</head>
<body>
<div class="container">
<h1>Ласкаво просимо!</h1>

<div class="nav">
<a href="/protected">Перейти до захищеного контенту</a>
</div>

<h2>Реєстрація</h2>
<form action="/auth/register" method="post">
<input type="email" name="email" placeholder="Email" required>
<input type="password" name="password" placeholder="Пароль" required>
<button type="submit">Зареєструватися</button>
</form>

<h2>Вхід</h2>
<form action="/auth/login" method="post">
<input type="email" name="email" placeholder="Email" required>
<input type="password" name="password" placeholder="Пароль" required>
<button type="submit">Увійти</button>
</form>
</div>
</body>
</html>
`);
});

app.get('/protected', (req, res) => {
if (!req.isAuthenticated()) {
return res.redirect('/');
}

res.send(`
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Захищений контент</title>
${styles}
</head>
<body>
<div class="container">
<h1>Захищений контент</h1>
<p>Ви авторизовані як: <strong>${req.user.email}</strong></p>
<form action="/auth/logout" method="get">
<button type="submit">Вийти</button>
</form>
</div>
</body>
</html>
`);
});

app.post('/auth/register', async (req, res) => {
try {
const { email, password } = req.body;
if (users.some(u => u.email === email)) {
return res.send(`
<div class="container">
<p class="error">Користувач з таким email вже існує</p>
<a href="/">Повернутися</a>
</div>
`);
}

const salt = await bcrypt.genSalt(10);
const hashedPassword = await bcrypt.hash(password, salt);

users.push({
id: Date.now().toString(),
email,
password: hashedPassword
});

res.send(`
<div class="container">
<p class="success">Користувач успішно зареєстрований!</p>
<a href="/">Увійти</a>
</div>
`);
} catch (error) {
res.status(500).send(`
<div class="container">
<p class="error">Помилка сервера</p>
<a href="/">Повернутися</a>
</div>
`);
}
});

app.post('/auth/login', (req, res, next) => {
passport.authenticate('local', (err, user, info) => {
if (err) return next(err);
if (!user) {
return res.send(`
<div class="container">
<p class="error">${info.message}</p>
<a href="/">Повернутися</a>
</div>
`);
}

req.logIn(user, (err) => {
if (err) return next(err);
return res.redirect('/protected');
});
})(req, res, next);
});

app.get('/auth/logout', (req, res) => {
req.logout(() => {
res.redirect('/');
});
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер працює на порті ${PORT}`));