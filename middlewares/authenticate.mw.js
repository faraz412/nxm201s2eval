const fs=require("fs");
const jwt=require("jsonwebtoken");
require("dotenv").config();

const authenticate=(req,res,next)=>{
    const token=req.headers.authorization;

    if(token){
        const blacklistedData=JSON.parse(fs.readFileSync("./blacklist.json","utf-8"));
        if(blacklistedData.includes(token)){
            return res.send({"msg":"Please Login"});
        }

        jwt.verify(token,process.env.normalKey,(err,decoded)=>{
            if(err){
                if(err.message=="jwt expired"){
                    const blacklistedData=JSON.parse(fs.readFileSync("./blacklist.json","utf-8"));
                    blacklistedData.push(token);
                    fs.writeFileSync("./blacklist.json",JSON.stringify(blacklistedData));   
                }
                res.send({"msg":"Please Login","err":err.message});
            }else{
                req.body.role=decoded.userRole;
                next();
            }
        })
    }else{
        res.send({"msg":"Not Authorized"});
    }
}

module.exports={authenticate};