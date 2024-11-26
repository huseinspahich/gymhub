import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import jwt from "jsonwebtoken";
import cookie from "cookie";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    maxAge: 1000 * 60 * 60 * 24,
}));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT
});

db.connect();

// JWT Functions
const generateAccessToken = (user) => {
    return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

const generateRefreshToken = (user) => {
    return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
};

const setRefreshTokenInCookie = (res, refreshToken) => {
    res.setHeader('Set-Cookie', cookie.serialize('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60, // 7 days
        sameSite: 'Strict',
        path: '/'
    }));
};

// Routes
app.get("/", (req, res) => {
    res.render("home.ejs")
});

app.get("/login", (req, res) => {
    res.render("login.ejs")
});

app.get("/register", (req, res) => {
    res.render("register.ejs")
});

app.get('/logout', (req, res) => {
    res.setHeader('Set-Cookie', cookie.serialize('refreshToken', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 0,
        sameSite: 'Strict',
        path: '/'
    }));
    res.redirect('/');
});

app.get("/site", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("site.ejs")
    } else {
        res.redirect("/login");
    }
});

const checkUserEmail = (req, res, next) => {
    if (req.isAuthenticated() && req.user.email === "harunhuseinspahic2001@gmail.com") {
        return next(); 
    } else {
        return res.redirect("/login"); 
    }
};

// Ruta za /protected koja koristi checkUserEmail middleware
app.get("/protected", checkUserEmail, (req, res) => {
    res.render("protected.ejs");
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['email', 'profile'] })
);

app.get('/auth/google/site',
    passport.authenticate('google', {
        successRedirect: '/site',
        failureRedirect: '/login'
    })
);

// Register route
app.post("/register", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;

    try {
        const checkResult = await db.query("SELECT * FROM users1 WHERE email = $1", [email]);
        if (checkResult.rows.length > 0) {
            res.send("Already exists");
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.log(err);
                } else {
                    const result = await db.query("INSERT INTO users1(email, password) VALUES ($1, $2) RETURNING id, email", [email, hash]);
                    const user = result.rows[0];

                    // Generate tokens
                    const accessToken = generateAccessToken(user);
                    const refreshToken = generateRefreshToken(user);

                    // Set refresh token in HttpOnly cookie
                    setRefreshTokenInCookie(res, refreshToken);

                    // Send access token in the response body
                    res.json({ accessToken, message: 'Registration successful!' });
                }
            });
        }
    } catch (error) {
        console.log(error);
    }
});

// Login route
app.post("/login", passport.authenticate("local", { failureRedirect: "/login" }), async (req, res) => {
    const user = req.user;

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    setRefreshTokenInCookie(res, refreshToken);

    res.json({ accessToken, message: 'Login successful!' });
});

// Local Strategy
passport.use("local", new Strategy(async function verify(username, password, cb) {
    try {
        const checkResult = await db.query("SELECT * FROM users1 WHERE email = $1", [username]);
        if (checkResult.rows.length === 0) {
            return cb("User not found");
        } else {
            const user = checkResult.rows[0];
            const userPassword = user.password;
            bcrypt.compare(password, userPassword, (err, result) => {
                if (err) {
                    return cb(err);
                } else {
                    if (result) {
                        return cb(null, user);
                    } else {
                        return cb(null, false);
                    }
                }
            })
        }
    } catch (error) {
        return cb(error)
    }
}));

// Google OAuth Strategy
passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/site',
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
}, async (request, accessToken, refreshToken, profile, cb) => {
    try {
        const result = await db.query("SELECT * FROM users1 WHERE email = $1", [profile.email]);
        if (result.rows.length === 0) {
            const newUser = await db.query("INSERT INTO users1 (email, password) VALUES ($1, $2)", [profile.email, "google"]);
            return cb(null, newUser.rows[0]);
        } else {
            return cb(null, result.rows[0]);
        }
    } catch (err) {
        return cb(err);
    }
}));

passport.serializeUser(function (user, cb) {
    return cb(null, user);
});

passport.deserializeUser(function (user, cb) {
    return cb(null, user);
});

// Refresh Token Route
app.post("/refresh-token", (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({ message: "Not authenticated" });
    }

    jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, async (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "Invalid refresh token" });
        }

        const newAccessToken = generateAccessToken(decoded);
        const newRefreshToken = generateRefreshToken(decoded);

        setRefreshTokenInCookie(res, newRefreshToken);

        res.json({ accessToken: newAccessToken });
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
