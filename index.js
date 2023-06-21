const express = require('express');
const ejs = require('ejs');
const dotenv = require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require("bcrypt");
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const app = express();
app.use(express.static('public'));
app.use(express.urlencoded({
    extended: false
}));

app.set('view engine', 'ejs');

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}))
app.use(passport.initialize());
app.use(passport.session());

const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PW,
    database: process.env.DB_DB
}

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next(); 
    }
    res.redirect('/users/login');
}

async function main(){
    try{
        const db = await mysql.createConnection(dbConfig);
        console.log("DB connected.");

        passport.use(new LocalStrategy(async function(username, password, done){
            const sql = 'SELECT * FROM users WHERE username = ?';
            const [user] = await db.query(sql, [username]);
            if (user.length == 0) {
                return done(null, false, {message:"Incorrect username"});
            }

            //const match = await bcrypt.compare(password, user[0].password);
            const match = password == user[0].password; //plain text checking, without hash
            if (!match) {
                return done(null, false, {message:"Incorrect password"});
            }
            return done(null, user[0]);  
        }));

        passport.serializeUser(function(user, done){
            done(null, user.user_id);
        });

        passport.deserializeUser(async function(id, done){
            const [user] = await db.query("SELECT * FROM users WHERE user_id = ?", [id]);
            done(null, user[0]);  
        });

        app.get('/', [ensureAuthenticated], async function(req,res){
            res.redirect("/owners");
        });

        app.get('/owners', [ensureAuthenticated], async function(req,res){
            const [owners] = await db.query("select * from owners");
            res.render("owners", { "owners":owners});
        });

        app.get('/owner/create', [ensureAuthenticated], function(req,res){
            res.render("create_owner");
        });
    
        app.post('/owner/create', async function(req,res){
            const {first_name, last_name,phone_number, email} = req.body;
            const sql = `INSERT INTO owners (first_name, last_name, phone_number, email) 
            VALUES (?,?,?,?)`;
            await db.query(sql, [first_name, last_name, phone_number, email]);
            res.redirect("/owners");
        });

        app.get('/owner/update/:owner_id', [ensureAuthenticated], async function(req,res){
            const {owner_id} = req.params;
            const [owners] = await db.query("select * from owners where owner_id = ?", owner_id);
            res.render("update_owner", { "owner":owners[0]});
        });

        app.post('/owner/update/:owner_id', async function(req,res){
            const {owner_id} = req.params;
            const {first_name, last_name,phone_number, email} = req.body;
            const sql = `UPDATE owners SET first_name=?, last_name=?, 
            phone_number=?, email=? WHERE owner_id=?`;
            await db.query(sql, [first_name, last_name,phone_number, email, owner_id]);
            res.redirect("/owners");
        });

        app.get('/owner/delete/:owner_id', [ensureAuthenticated], async function(req,res){
            const {owner_id} = req.params;
            const [owners] = await db.query("select * from owners where owner_id = ?", owner_id);
            res.render("delete_owner", { "owner":owners[0]});
        });

        app.post('/owner/delete/:owner_id', async function(req,res){
            const {owner_id} = req.params;
            const sql = `DELETE FROM owners WHERE owner_id=?`;
            await db.query(sql, [owner_id]);
            res.redirect("/owners");
        });

        app.get('/users/register', async function(req, res){
            const [roles] = await db.query("select * from roles");
            res.render("register", {roles});
        });

        app.post('/users/register', async function(req,res){
            const {first_name, last_name, username, email, password, role} = req.body;
            //const hashedPW = await bcrypt.hash(password, 10);
            const sql = `INSERT INTO users (username, password, first_name, last_name, email) 
            VALUES (?,?,?,?,?)`;
            const [result] = await db.query(sql, [username, password, first_name, last_name, email]);
            const insertId = result.insertId;
            const sql2 = `INSERT INTO user_roles (user_id, role_id) 
            VALUES (?,?)`;
            await db.query(sql2, [insertId, role]);
            res.redirect("/users/login");
        })

        app.get('/users/login', function(req,res){
            res.render("login");
        });

        app.post('/users/login', async function(req,res,next){
            passport.authenticate('local', function(err, user, info){
                if (err) {
                    return next(err);
                }
                if (!user) {
                    return res.redirect('/login');
                }
                req.login(user, (err)=>{
                    if (err) {
                        return next(err);
                    }
                    return res.redirect('/');
                })

            })(req, res, next);
        });


        app.get('/users/logout', function(req,res){
            res.render("logout");
        });

        app.post('/users/logout', function(req,res){
            req.logout(function(e){
                if (e) {
                    console.error("Error destroying session:", err);
                    return res.status(500).send('Error destroying session');
                } else {
                    res.redirect('/users/login');
                }
            });
        });

    } catch (e) {
        console.log("Error==>",e);
        res.status(500);
        res.send("Error encountered.");
    }

    
}

main()

app.listen(process.env.port || 3000, function(){
    console.log("server has started");
})