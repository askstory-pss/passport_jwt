const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const router = express.Router();
const crypto = require("crypto");
const util = require('util');
const sgMail = require("@sendgrid/mail");

const config = require('../config');
const dbConfig = config.database;
const mysql = require('mysql2');
const db = mysql.createPool({
  host: dbConfig.host,
  port: dbConfig.port,
  user: dbConfig.user,
  password: dbConfig.password,
  database: dbConfig.database,
});

sgMail.setApiKey(process.env.MAIL_API_KEY);

const users = [];

// 회원 가입
router.post("/register", async (req, res) => {
  try {
    let { name, email, employeeNumber, pw, hp, subject, position, duty } = req.body;

    if(hp === "") hp = null;
    if(duty === "") duty = null;

    // subject = 1 // 부서ID 임시 처리

    let today = new Date();

    const hashedPassword = await bcrypt.hash(pw, 10);
    const newUser = { email, pw: hashedPassword };

    db.query('INSERT INTO USER (USER_NAME, EMAIL, USER_NO, PASSWD, HP, DEPART_ID, GRADE, POSITION, REG_DATE) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [name, email, employeeNumber, hashedPassword, hp, subject, position, duty, today], (err, result) => {
      if (err) throw err;
    });

    res
      .status(201)
      .json({ message: "User registered successfully", user: newUser });
  } catch (e) {
    console.log(e.message);
  }
});

// 로그인
router.post("/login", async (req, res) => {
  try {
    const { email, pw } = req.body;

    const query = util.promisify(db.query).bind(db);
    
    const rows = await query('SELECT * FROM USER WHERE EMAIL = ?', [email]);

    if (!rows.length) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const user = rows[0];
    const passwordMatch = await bcrypt.compare(pw, user.PASSWD);

    if (!passwordMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const newUser = { email };

    users.push(newUser);

    const refreshToken = crypto.randomBytes(64).toString("hex");
    newUser.refreshToken = refreshToken;
    const accessToken = jwt.sign(
      { email: user.email },
      process.env.JWT_SECRET,
      {
        expiresIn: "1m",
      }
    );

    await query('UPDATE USER SET ACCESS_TOKEN = ?, REFRESH_TOKEN = ? WHERE EMAIL = ?', [accessToken, refreshToken, email]);

    res.json({ message: "Logged in successfully", accessToken, refreshToken, user });
  } catch (e) {
    console.log(e.message);
  }
});

// access token 재발행
router.post("/token", async (req, res) => {
  const { refreshToken } = req.body;
  const user = users.find((u) => u.refreshToken === refreshToken);
  if (!user) {
    return res.status(403).json({ message: "Invalid refresh token" });
  }
  const newToken = jwt.sign(
    { username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "1m" }
  );

  const query = util.promisify(db.query).bind(db);

  await query('UPDATE USER SET ACCESS_TOKEN = ? WHERE REFRESH_TOKEN = ?', [newToken, refreshToken]);

  res.json({ message: "New access token generated", accessToken: newToken });
});

// 로그 아웃
router.post("/logout", async (req, res) => {
  const { refreshToken } = req.body;
  const user = users.find((u) => u.refreshToken === refreshToken);
  if (!user) {
    return res.status(400).json({ message: "Invalid refresh token" });
  }

  const query = util.promisify(db.query).bind(db);

  await query('UPDATE USER SET REFRESH_TOKEN = null WHERE REFRESH_TOKEN = ?', [refreshToken]);

  user.refreshToken = null;
  res.json({ message: "User logged out successfully" });
});

// 중복 확인
router.post('/checkDuplicates', async (req, res) => {
  const email = req.body.email;
  const employeeNumber = req.body.employeeNumber;

  if(email !== undefined){
    try {
      const isDuplicate = await checkForDuplicate(email, 'EMAIL');
      const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
      res.json({ isDuplicate: isDuplicate, emailRegex : emailRegex.test(email) });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred' });
    }
  }else if(employeeNumber !== undefined){
    try {
      const isDuplicate = await checkForDuplicate(employeeNumber, 'USER_NO');
      res.json({ isDuplicate: isDuplicate });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred' });
    }
  }
});

// 비밀번호 변경
router.post("/reset-password", async (req, res) => {
  const { email, name } = req.body;
  const randomPassword = generateRandomPassword();
  const hashedPassword = await bcrypt.hash(randomPassword, 10);
  const query = util.promisify(db.query).bind(db);

  const rows = await query('SELECT * FROM USER WHERE EMAIL = ? and USER_NAME = ?', [email, name]);

  if(rows.length === 1){
    await query('UPDATE USER SET PASSWD = ?, SHOULD_CHANGE_PW = "Y" WHERE EMAIL = ?', [hashedPassword, email]);

    const msg = {
      to: email,
      from: 'askstoryteam@gmail.com', // Change to your verified sender
      subject: '임시 비밀 번호 발급',
      text: `임시 비밀 번호 : ${randomPassword}`,
      html: `<strong>임시 비밀 번호 : ${randomPassword}</strong>`,
    }
    sgMail
      .send(msg)
      .then(() => {
        console.log('Email sent')
      })
      .catch((error) => {
        console.error(error)
      })
    //res.redirect("/");
    res.status(200);
  } else {
    res.status(400).json({ error: 'Not Match Info' });
  }
});

router.get("/depart", async (req, res) => {
  try {
    let departInfo = await getDepartInfo();

    res
      .status(201)
      .send(departInfo);
  } catch (e) {
    console.log(e.message);
  }
});


async function checkForDuplicate(itemValue, item) {
  return new Promise((resolve, reject) => {
    db.query(`SELECT * FROM USER WHERE ${item} = ?`, [itemValue], (err, rows) => {
      if (err) {
        reject(err);
      } else {
        if (rows.length > 0) {
          resolve(false);
        } else {
          resolve(true);
        }
      }
    });
  });
}

function generateRandomPassword() {
  return Math.floor(Math.random() * 10 ** 8)
    .toString()
    .padStart("0", 8);
}

async function getDepartInfo() {
  return new Promise((resolve, reject) => {
    db.query(`SELECT DEPART_ID, DEPART_NAME FROM DEPARTMENT WHERE USE_YN = "Y"`, (err, rows) => {
      if (err) {
        reject(err);
      } else {
        if (rows.length > 0) {
          resolve(rows);
        } else {
          resolve(false);
        }
      }
    });
  });
}

module.exports = { router, users, db };