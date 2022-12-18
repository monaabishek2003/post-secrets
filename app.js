
require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose")
const encrypt = require("mongoose-encryption")
const session = require("express-session")
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const bcrypt = require("bcrypt");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');



// const md5 = require("md5")

const saltRounds = 10;

const app = express();
app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));


//these are made to use cookieees and sessions
app.use(session({secret:"Our little secret",resave:false,saveUninitialized:false}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema =new mongoose.Schema({
    email : String,
    password  :String,
    googleId  :String,
    secret :String
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt, { secret: process.env.SECRET,encryptedFields:["password"]});


const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());
passport.serializeUser((user,done)=>{
    done(null,user.id);
});
passport.deserializeUser((id,done)=>{
    User.findById(id,function(err,user){
        done(err,user)
    })
});
passport.use(new GoogleStrategy({
    clientID:     process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(request, accessToken, refreshToken, profile, done) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

app.get("/",(req,res)=>{
    res.render("home");
})

app.get("/auth/google",
    passport.authenticate("google",
    {
        scope:["profile"]
    }
    )
);

app.get("/auth/google/callback",
    passport.authenticate("google",
    {
        failureRedirect: "/login"
    }),
    function(req,res){
        res.redirect("/secrets");
    }
);

app.get("/login",(req,res)=>{
    res.render("login");
})

app.get("/register",(req,res)=>{
    res.render("register");
})


app.get('/logout', function(req, res, next) {
    req.logout(function(){});
    res.redirect("/")
  });


app.get("/secrets",(req,res)=>{
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
        if (err){
          console.log(err);
        } else {
          if (foundUsers) {
            res.render("secrets", {usersWithSecrets: foundUsers});
          }
        }
      });
});



app.post("/register",(req,res)=>{

    User.register({username:req.body.username},req.body.password,function(err,user){
        if(!err){
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets")
            });
        }else{
            console.log(err);
            res.redirect("/login");
        };
    })



})
app.post("/login",(req,res)=>{
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user,function(err){
        if(!err){
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets")
            });
        }else{
            console.log(err);
            res.redirect("/login");
        };
    })
})

app.get("/submit",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
})

app.post("/submit",(req,res)=>{
    const submittedSecret = req.body.secret;
    User.findById(req.user.id,(err,founduser)=>{
        if(founduser){
            founduser.secret = submittedSecret;
            founduser.save(()=>{
                res.redirect("/secrets")
            })
        }else{
            if(err){
                console.log(err);
            }
        }
        
    })
})

app.listen(3000,()=>{
    console.log("server is up do whatever u want")
})

// //code inside login route bcrypt
// // const email = req.body.username;
// // const password = req.body.password;
// // User.findOne({email:email},(err,founduser)=>{
// //     if(!err){
// //         if(founduser){
// //             bcrypt.compare(password, founduser.password,(err,result)=>{
// //                 // result == true
// //                 if(!err){
// //                     if(result){
// //                         res.render("secrets");
// //                     }else{
// //                         res.send("Invalid Login")
// //                     }
// //                 }else{
// //                     res.send(err);
// //                 }
// //             });
// //         }else{
// //             res.send("Invalid Login")
// //         }
// //     }else{
// //         res.send(err);
// //     }
// // })

//     //code to authenticate usong hashig and salting
//     // bcrypt.hash(req.body.password, saltRounds,(err,hash)=> {
//     //     // Store hash in your password DB.
//     //     if(!err){
//     //         const newUser = new User({
//     //         email:req.body.username,
//     //         password:hash
//     //         })
//     //         newUser.save((err)=>{
//     //         if(!err){
//     //             res.render("secrets");
//     //         }else{
//     //             res.send(err);
//     //         }
//     //         });
//     //     }else{
//     //         res.send(err);
//     //     }
//     // });