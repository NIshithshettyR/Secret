//jshint esversion:6
require('dotenv').config();

const express = require('express');
const app = express();

const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportlocalmongoose = require('passport-local-mongoose');
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

app.use(session({
secret : "This is passport.",
resave : false,
saveUninitialized : false
}));

app.use(passport.initialize());
app.use(passport.session());


// const bcrypt = require('bcrypt');
// const saltrounds = 10;
// const md5 = require("md5");
// const encrypt = require("mongoose-encryption");

const URL = "mongodb://localhost:27017/userDB";
mongoose.connect(URL , {useNewUrlParser:true , useUnifiedTopology : true , useCreateIndex:true});


// user Schema
const userSchema = new mongoose.Schema({
email : String,
password : String,
googleId : String,
facebookId: String,
secrets : String
});

userSchema.plugin(passportlocalmongoose);
userSchema.plugin(findOrCreate);

// Encrypt or do anything , before modelling.
// userSchema.plugin(encrypt , {secret : process.env.SECRET , encryptedFields : ['password']});

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy(
{
clientID : process.env.CLIENT_ID,
clientSecret : process.env.CLIENT_SECRET,
callbackURL : "http://localhost:3000/auth/google/Secrets",
userProfileURL : "https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken , refreshToken , profile ,cb){
    console.log(profile);
    User.findOrCreate({googleId : profile.id , username:profile.displayName},function(err , user){
        return cb(err , user);
    });
}
));

passport.use(new FacebookStrategy(
{
clientID : process.env.FACEBOOK_CLIENT_ID,
clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
callbackURL :"http://localhost:3000/auth/facebook/Secrets",
userProfileURL :"https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken , refreshToken , profile ,cb){
    console.log(profile);
    User.findOrCreate({ facebookId : profile.id },function(err , user){
        return cb(err , user);
    });
}
));

app.use(bodyParser.urlencoded({extended:true}));

app.set("view engine","ejs");

app.use(express.static("public"));

app.get("/",function(req , res){
res.render("home");
});

app.get("/login",function(req , res){
    res.render("login");
});

app.get("/register",function(req , res){
    res.render("register");
});

app.get("/submit",function(req , res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit",function(req , res){
const getSecret = req.body.secret;

User.findById(req.user.id , function(err , result){
if(err){
    console.log(err);
}else{
    if(result){
        result.secrets = getSecret;
        result.save(function(){
            res.redirect("/secrets");
        });
    }
}
});
});

app.get("/auth/google",
passport.authenticate("google" , {scope : ["profile"]}));

app.get("/auth/facebook",
passport.authenticate("facebook" , {scope : ["public_profile"]}));

app.get("/auth/facebook/Secrets",
passport.authenticate("facebook", { failureRedirect: "/login" }),
function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/Secrets");
});

app.get("/auth/google/Secrets",
passport.authenticate("google", { failureRedirect: '/login' }),
function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/Secrets");
});

app.get("/Secrets",function(req , res){
    if(req.isAuthenticated()){
        User.find({secrets : {$ne:null}},function(err , result){
            res.render("Secrets",{userSecret : result});
        });
    }else{
        res.redirect("/login");
    }
});

app.post("/register",function(req , res){

    User.register({username : req.body.username} , req.body.password,function(err , result){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req, res ,function(){
                res.redirect("/Secrets");
            });
        }
    });

        // bcrypt.hash( req.body.password , saltrounds ,function(err , hash){
        //     if(!err){
        //         const user1 = new User({
        //             email : req.body.username,
        //             password: hash
        //             });
        //             user1.save(function(err){
        //                 if(!err){
        //                     res.render("secrets");
        //                 }
        //             });
        //     }
        // });
});

app.post("/login" , function(req , res){
    const user = new User({
        email : req.body.username,
        password : req.body.password
    });

    req.logIn(user , function(err){
if(err){
    console.log(err);
    res.redirect("/login");
}else{
    passport.authenticate("local")(req ,res ,function(){
        res.redirect("/Secrets");
    });
}
    });
// User.findOne({email : username},function(err,userfound){
//     if(!err){
//     if(userfound.email){
//        bcrypt.compare(password , userfound.password , function(err , result){
//         if(result === true){
//             res.render("secrets");
//         }else{
//             console.log(err);
//         }
//        });
//     }
// }
// });

});

app.get("/logout" , function(req ,res){
req.logout();
res.redirect("/");
});



app.listen(3000,function(){
console.log("Server started on port 3000 successfully");
});
