import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import {Strategy} from "passport-local";
import GoogleStrategy from "passport-google-oauth2"; 
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));

app.use(session ({
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

app.get("/", (req,res) => {
    res.render("home.ejs")
});

app.get("/login", (req,res) => {
    res.render("login.ejs")
});

app.get("/register", (req,res) => {
    res.render("register.ejs")
});

app.get('/logout', (req, res) => {
    req.logout(function(err) {
      if (err) {
         return next(err);
         };
      res.redirect('/');
    });
  });

app.get("/site", (req,res) => {
    if (req.isAuthenticated) {
        res.render("site.ejs")
    } else {
        res.redirect("/login");   
    }
});

app.get('/auth/google',
    passport.authenticate('google', { scope:
        [ 'email', 'profile' ] }
  ));

  app.get('/auth/google/site',
    passport.authenticate('google', {
        successRedirect: '/site',
        failureRedirect: '/login'
}));
  
app.post("/register", async(req,res) => {
    const email = req.body.username;
    const password = req.body.password;
    
    try {
        const checkResult = await db.query("SELECT * FROM users1 WHERE email = $1",[email]);
        if (checkResult.rows.length > 0) {
            res.send("Already exists");
        } else {
            bcrypt.hash(password,saltRounds,async (err,hash) =>{
                if (err) {
                    console.log(err)
                } else {
                    const result = await db.query("INSERT INTO users1(email,password) VALUES ($1,$2)",[email,hash]);
                    const user = result.rows[0];
                    req.login(user,(err) => {
                        console.log(err);
                        res.redirect("/site")
                    })
                }
            })
        }
    } catch (error) {
        console.log(error);
    }
});

app.post("/login", passport.authenticate("local",{
    successRedirect: "/site",
    failureRedirect:"/login"
}));
passport.use("local",new Strategy(async function verify(username, password, cb) {
    try {
        const checkResult = await db.query("SELECT * FROM users1 WHERE email = $1",[username]);
        if (checkResult.rows.length === 0) {
            return cb("User not found");
        } else {
            const user = checkResult.rows[0];
            const userPassword = user.password;
            bcrypt.compare(password, userPassword, (err,result) => {
                if (err) {
                    return cb(err);
                } else {
                    if (result) {
                        return cb(null, user);
                    } else {
                        return cb(null,false);
                    }
                }
            })
        }
    } catch (error) {
        return cb(error)
    }
  }));
  passport.use("google",new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/site',
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  async (request, accessToken, refreshToken, profile, cb) => {
    try {
        console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser(function(user, cb) {
    return cb(null, user);
});  

passport.deserializeUser(function(user, cb) {
      return cb(null, user);
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
})