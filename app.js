//jshint esversion:6
require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

//----------------------------------

app.use(session({
    secret:"AlyssaSecret",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

/*   ---------------------------
    USE EXPRESS/PASSPORT SESSION
    BEFORE CONNECTING TO MONGOOSE
    ----------------------------   */


mongoose.connect("mongodb://localhost:27017/passwordDB", {useNewUrlParser: true});
mongoose.set("useCreateIndex", true);
//new mongoose.Schema because we are adding plugin next
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String
});
//Plugin will salt and hash our passwords
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  }); 

//AUTHENTICATE WITH GOOGLE
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/appConAuth",
    //Google+ deprication. requires this new strategy
    userProfileUrl: "https://googleapis.com/oauth2/v3/userinfo"
},
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google", passport.authenticate('google', {

    scope: ["profile"]

}));

app.get('/auth/google/appConAuth', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/secrets", function(req, res){
    if (req.isAuthenticated()){
        res.render("secrets");
    }else{
        res.redirect("/login");
    }
});

app.post("/register", function(req, res){
    //passport lcoal mongoose 
    User.register({username: req.body.username}, req.body.password), function(err, user){
     if (err){
         console.log(err);
         res.redirect("/register");
     }   else{
         passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets");
         });
     }
    }
});

app.get("/register", function(req, res){
    res.render("register");
});


app.post("/login", function(req, res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if(err){
            console.log(err);
        } else{
            passport.authenticate("local");
            res.redirect("/secrets");
        }
    })
});


app.get("/logout", function(req, res){
    req.logout();
    res.redirect("/");
});







app.listen(3000, function(){
   console.log("server started on port 3000");
});