require('dotenv').config();

const express = require('express');
const mysql = require('mysql');
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const app = express();
const PORT = 3000;

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) throw err;
    console.log("MYSQL 연결 성공!");
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: true,
}));
app.use(express.static("public"));

app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});

app.post("/", async (req, res) => {
    const { email, username, password, action } = req.body;

    if (action === "register") {
        // 회원가입 처리
        if (!email || !password || !username) {
            return res.send("모든 필드를 입력하세요.");
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const query = "INSERT INTO users (email, username, password) VALUES (?, ?, ?)";
        db.query(query, [email, username, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === "ER_DUP_ENTRY") {
                    return res.send("이미 존재하는 사용자입니다.");
                }
                throw err;
            }
            res.send("회원가입 성공!");
        });
    } else if (action === "login") {
        // 로그인 처리
        if (!email || !password) {
            return res.send("모든 필드를 입력하세요.");
        }

        const query = "SELECT * FROM users WHERE email = ?";
        db.query(query, [email], async (err, results) => {
            if (err) throw err;

            if (results.length === 0) {
                return res.send("사용자를 찾을 수 없습니다.");
            }

            const user = results[0];
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.send("비밀번호가 일치하지 않습니다.");
            }

            req.session.user = user;
            res.send("로그인 성공!");
        });
    }
});

app.listen(PORT, () => {
    console.log(`서버가 http://localhost:${PORT} 에서 실행 중입니다.`);
});
