const express= require("express");
const {connection}=require("./config/db.js");
const {UserModel}=require("./models/user.model.js");
const bcrypt=require("bcrypt");
const jwt=require("jsonwebtoken");
const fs=require("fs");
const {authenticate}=require("./middlewares/authenticate.mw.js");
const {authorize}=require("./middlewares/authorize.mw.js");
require("dotenv").config();

const app=express();
app.use(express.json());

app.get("/", (req,res)=>{
    res.send("WELCOME TO HOMEPAGE");
})

app.post("/signup",async(req,res)=>{
    const {name,email,password,role}=req.body;
    try{
        const check=await UserModel.find({email});
        if(check.length>0){
            res.send({"msg":"Please Login"});
        }else{
            bcrypt.hash(password,7,async(err,hash)=>{
                if(err){
                    res.send({"bcrypt-hash-err":err});
                }else{
                    const user=await UserModel({name,email,password:hash,role});
                    await user.save();
                    res.send({"msg":"Registered"});
                }
            })
        }
    }catch(err){
        res.send({"signup-err":err});
    }
})

app.post("/login",async(req,res)=>{
    const {email,password}=req.body;
    try{
        const user=await UserModel.find({email});
        if(user.length>0){
            bcrypt.compare(password,user[0].password,(err,result)=>{
                if(err){
                    res.send({"bcrypt-compare-err":err});
                }else{
                    const normalToken=jwt.sign({userID:user[0]._id,userRole:user[0].role},process.env.normalKey,{expiresIn:10});
                    const refreshToken=jwt.sign({userID:user[0]._id,userRole:user[0].role},process.env.refreshKey,{expiresIn:30});
                    res.send({"msg":"Login Succesfull","token":normalToken,"refreshToken":refreshToken});
                }
            })
        }else{
            res.send({"msg":"Wrong credentials"});
        }
    }catch(err){
        res.send({"login-err":err});
    }
})

app.get("/getNewToken",async(req,res)=>{
    const refreshToken=req.headers.authorization;
    try{
        if(!refreshToken){
            res.send({"msg":"Please Login"});
        }else{
            jwt.verify(refreshToken,process.env.refreshKey,(err,decoded)=>{
                if(err){
                    res.send({"msg":"Please Login","err-refereshToken":err.message});
                }else{
                    const new_token=jwt.sign({userID:decoded._id,userRole:decoded.role},process.env.normalKey,{expiresIn:60});
                    res.send({"token":new_token});
                }
            })
        }
    }catch(err){
        res.send({"msg":"Please Login"});
    }
})

app.get("/logout",async(req,res)=>{
    const token=req.headers.authorization;
    //console.log(token);
    const blacklistedData=JSON.parse(fs.readFileSync("./blacklist.json","utf-8"));
    blacklistedData.push(token);
    fs.writeFileSync("./blacklist.json",JSON.stringify(blacklistedData));
    res.send({"msg":"Logged out succesfully"});
})

app.get("/goldrate",authenticate,async(req,res)=>{
    res.send("GOLDRATES PAGE");
})

app.get("/userstats",authenticate,authorize(["manager"]),async(req,res)=>{
    res.send("USER STATS PAGE");
})



app.listen(process.env.port, async()=>{
    try{
        await connection;
        console.log("Connected to DB");
    }catch(err){
        console.log("Error in connecting to DB");
    }
    console.log(`Listening on port ${process.env.port}`);
})
