//jshint esversion:6
const express=require("express");
require("dotenv").config();
const ejs=require("ejs");
const _=require("lodash");
const mongoose=require("mongoose");
const body=require("body-parser");
const session=require("express-session");
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');





const app=express();
app.set("view engine","ejs");
app.use(express.static("public"));
app.use(body.urlencoded({extended:true}));
app.use(session({
    secret:process.env.SECRET,
    resave:false,
    saveUninitialized:true,
}));
app.use(passport.initialize());
app.use(passport.session());
mongoose.connect(process.env.LINK,{useNewUrlParser:true,useUnifiedTopology:true});
mongoose.set("useCreateIndex",true);

const userSchema=new mongoose.Schema({
    name:String,
    username:String,
    password:String,
    googleId:String
}, {
    writeConcern: {
      w: 'majority',
      j: true,
      wtimeout: 1000
    }});
const secretSchema=new mongoose.Schema({
    content:String,
    name:String
});
const Secret=mongoose.model("Secret",secretSchema);

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User=mongoose.model("User",userSchema);
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID:process.env.CLIENT_ID,
    clientSecret:process.env.CLIENT_SECRET,
    callbackURL: "https://thawing-river-18412.herokuapp.com/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id,name:(_.capitalize(profile.name.givenName))}, function (err, user) {
      return cb(err, user);
    });
  }
));



app.get("/",function(req,res){
    if(req.isAuthenticated()){
        res.redirect("/secrets");
    }else{
        res.render("home");
    }
});
app.get("/login",function(req,res){
    res.render("login");
});
app.get("/register",function(req,res){
    res.render("register");
});
app.get("/secrets",function(req,res){
    if(req.isAuthenticated()){
        const head=req.user.name
        Secret.find({content:{$ne:null}},function(err,found){
            if(!err){
                if(found){
                    res.render("secrets",{found:found,head:head});
                }
            }
        });
    }else{
        res.redirect("/");
    }
});
app.get("/logout",function(req,res){
    req.logout();
    res.redirect("/");
}); 
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
});
app.get("/submit",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit")
    }else{
        res.redirect("/");
    }
})



app.post("/register",function(req,res){
    User.register({username:req.body.username,name:_.capitalize(req.body.name)},req.body.password,function(err,val){
        if(err){
            console.log(err);
            res.redirect("/");
        }else{
            val.save();
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });       
        }
    });
});
    
app.post("/login",function(req,res){
    newUser=new User({
        username:req.body.username,
        password:req.body.password
    });
    req.login(newUser,function(err){
        if(!err){
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }else{ 
            console.log(err);
            res.redirect("/login");
        }
    });   
});
app.post("/submit",(req,res)=>{
    const content=req.body.secret;
    let secretName="Anonymous"
    if(req.body.secret_name!==""){secretName=req.body.secret_name}
    
    newSecret=new Secret({
        content:content,
        name:secretName
    });
    newSecret.save();
    res.redirect("/secrets");
      
});
app.listen(process.env.PORT||8000,()=>console.log("port 8000 is active"));