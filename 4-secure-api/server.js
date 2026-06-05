/*
	Week 4 Secure API App
	Advanced Threat Detection & Web Security Enhancements
	Author: Muhammad Hamza Naseer
*/

const express=require("express");
const helmet=require("helmet");
const cors=require("cors");
const rateLimit=require("express-rate-limit");
const jwt=require("jsonwebtoken");
const bcrypt=require("bcryptjs");
const winston=require("winston");
const fs=require("fs");
const https=require("https");
const path=require("path");
const crypto=require("crypto");
const {execSync}=require("child_process");

const app=express();

const PORT=3443;
const JWT_SECRET="week4_super_secure_jwt_secret_2026";
const API_KEY="devhub-week4-api-key-12345";
const ALLOWED_ORIGIN="https://localhost:3443";

app.set("trust proxy","loopback");
app.use(express.json());
app.use(express.urlencoded({extended:false}));

const logsDir=path.join(__dirname,"logs");
const certDir=path.join(__dirname,"cert");
const publicDir=path.join(__dirname,"public");

if(!fs.existsSync(logsDir)){
	fs.mkdirSync(logsDir);
}

if(!fs.existsSync(certDir)){
	fs.mkdirSync(certDir);
}

const logger=winston.createLogger({
	level:"info",
	format:winston.format.combine(
		winston.format.timestamp(),
		winston.format.printf(info=>`${info.timestamp} [${info.level.toUpperCase()}] ${info.message}`)
	),
	transports:[
		new winston.transports.File({filename:path.join(logsDir,"security.log")}),
		new winston.transports.Console()
	]
});

function getClientIp(req){
	let ip=req.ip||req.connection.remoteAddress||"unknown";
	ip=ip.replace("::ffff:","");
	if(ip==="::1"){
		ip="127.0.0.1";
	}
	return ip;
}

function ensureCertificates(){
	const keyPath=path.join(certDir,"key.pem");
	const certPath=path.join(certDir,"cert.pem");

	if(fs.existsSync(keyPath)&&fs.existsSync(certPath)){
		return;
	}

	try{
		execSync(`openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 -keyout "${keyPath}" -out "${certPath}" -subj "/CN=localhost"`,{stdio:"ignore"});
		logger.info("SELF_SIGNED_CERTIFICATE_CREATED");
	}catch(error){
		console.log("Certificate generation failed.");
		console.log("Run these commands manually:");
		console.log("mkdir cert");
		console.log('openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 -keyout cert/key.pem -out cert/cert.pem -subj "/CN=localhost"');
		process.exit(1);
	}
}

const users=[
	{
		id:1,
		username:"admin",
		passwordHash:bcrypt.hashSync("Admin@12345",10),
		role:"administrator"
	}
];

app.use((req,res,next)=>{
	res.locals.cspNonce=crypto.randomBytes(16).toString("base64");
	next();
});

app.use(helmet({
	contentSecurityPolicy:{
		useDefaults:true,
		directives:{
			"default-src":["'self'"],
			"script-src":["'self'",(req,res)=>`'nonce-${res.locals.cspNonce}'`],
			"style-src":["'self'",(req,res)=>`'nonce-${res.locals.cspNonce}'`],
			"img-src":["'self'","data:"],
			"connect-src":["'self'"],
			"object-src":["'none'"],
			"frame-ancestors":["'none'"],
			"base-uri":["'self'"],
			"form-action":["'self'"],
			"script-src-attr":["'none'"]
		}
	},
	strictTransportSecurity:{
		maxAge:31536000,
		includeSubDomains:true,
		preload:true
	},
	xFrameOptions:{
		action:"deny"
	},
	xContentTypeOptions:true,
	referrerPolicy:{
		policy:"no-referrer"
	}
}));

app.use(cors({
	origin:function(origin,callback){
		if(!origin||origin===ALLOWED_ORIGIN){
			callback(null,true);
		}else{
			logger.warn(`CORS_BLOCKED origin=${origin}`);
			callback(new Error("CORS policy blocked this request"));
		}
	},
	methods:["GET","POST"],
	allowedHeaders:["Content-Type","Authorization","x-api-key"],
	credentials:false
}));

const loginLimiter=rateLimit({
	windowMs:15*60*1000,
	max:5,
	standardHeaders:true,
	legacyHeaders:false,
	handler:(req,res)=>{
		const ip=getClientIp(req);
		logger.warn(`BRUTE_FORCE_ATTEMPT ip=${ip} endpoint=/api/login`);
		res.status(429).json({
			error:"Too many login attempts. Try again after 15 minutes."
		});
	}
});

const apiLimiter=rateLimit({
	windowMs:10*60*1000,
	max:30,
	standardHeaders:true,
	legacyHeaders:false,
	message:{
		error:"Too many API requests. Please slow down."
	}
});

function verifyJwt(req,res,next){
	const authHeader=req.headers.authorization;

	if(!authHeader||!authHeader.startsWith("Bearer ")){
		return res.status(401).json({error:"Missing or invalid token"});
	}

	const token=authHeader.split(" ")[1];

	try{
		const decoded=jwt.verify(token,JWT_SECRET);
		req.user=decoded;
		next();
	}catch(error){
		return res.status(403).json({error:"Invalid or expired token"});
	}
}

function verifyApiKey(req,res,next){
	const apiKey=req.headers["x-api-key"];

	if(!apiKey||apiKey!==API_KEY){
		const ip=getClientIp(req);
		logger.warn(`INVALID_API_KEY ip=${ip} endpoint=${req.originalUrl}`);
		return res.status(401).json({error:"Invalid API key"});
	}

	next();
}

app.get("/",(req,res)=>{
	const indexPath=path.join(publicDir,"index.html");

	fs.readFile(indexPath,"utf8",(err,html)=>{
		if(err){
			logger.error(`INDEX_LOAD_ERROR message=${err.message}`);
			return res.status(500).send("Frontend file not found.");
		}

		const finalHtml=html.split("{{NONCE}}").join(res.locals.cspNonce);
		res.type("html").send(finalHtml);
	});
});

app.get("/api/security-status",(req,res)=>{
	res.json({
		status:"secure",
		https:"enabled",
		jwt:"enabled",
		apiKey:"enabled",
		rateLimiting:"enabled",
		cors:"restricted",
		csp:"enabled",
		hsts:"enabled",
		logging:"enabled",
		fail2ban:"supported"
	});
});

app.post("/api/login",loginLimiter,(req,res)=>{
	const ip=getClientIp(req);
	const {username,password}=req.body;

	if(!username||!password){
		logger.warn(`AUTH_FAIL ip=${ip} reason=missing_credentials`);
		return res.status(400).json({error:"Username and password required"});
	}

	const user=users.find(u=>u.username===username);

	if(!user){
		logger.warn(`AUTH_FAIL ip=${ip} username=${username} reason=user_not_found`);
		return res.status(401).json({error:"Invalid credentials"});
	}

	const isValid=bcrypt.compareSync(password,user.passwordHash);

	if(!isValid){
		logger.warn(`AUTH_FAIL ip=${ip} username=${username} reason=wrong_password`);
		return res.status(401).json({error:"Invalid credentials"});
	}

	const token=jwt.sign(
		{id:user.id,username:user.username,role:user.role},
		JWT_SECRET,
		{expiresIn:"30m"}
	);

	logger.info(`AUTH_SUCCESS ip=${ip} username=${username}`);

	res.json({
		message:"Login successful",
		token:token
	});
});

app.get("/api/secure-data",apiLimiter,verifyApiKey,verifyJwt,(req,res)=>{
	res.json({
		message:"Secure API data accessed successfully",
		user:req.user.username,
		role:req.user.role,
		security:[
			"JWT authentication enabled",
			"API key protection enabled",
			"Rate limiting enabled",
			"CORS restricted",
			"CSP enabled",
			"HSTS enabled",
			"Security logging enabled",
			"Fail2Ban monitoring supported"
		]
	});
});

app.post("/api/report-threat",apiLimiter,verifyApiKey,verifyJwt,(req,res)=>{
	const ip=getClientIp(req);
	const {event,severity}=req.body;

	logger.warn(`THREAT_REPORT ip=${ip} user=${req.user.username} event=${event||"unknown"} severity=${severity||"medium"}`);

	res.json({
		message:"Threat report logged successfully",
		event:event||"unknown",
		severity:severity||"medium"
	});
});

app.use((err,req,res,next)=>{
	logger.error(`SERVER_ERROR message=${err.message}`);
	res.status(500).json({error:"Internal server error"});
});

ensureCertificates();

const sslOptions={
	key:fs.readFileSync(path.join(certDir,"key.pem")),
	cert:fs.readFileSync(path.join(certDir,"cert.pem"))
};

https.createServer(sslOptions,app).listen(PORT,()=>{
	logger.info(`SECURE_SERVER_STARTED https://localhost:${PORT}`);
	console.log(`Secure Week 4 app running at https://localhost:${PORT}`);
	console.log("Default login: admin / Admin@12345");
	console.log("API key: devhub-week4-api-key-12345");
});
