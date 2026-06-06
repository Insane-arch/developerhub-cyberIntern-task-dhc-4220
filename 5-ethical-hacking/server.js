/*
	Week 5 Ethical Hacking Lab
	SQL Injection Testing, SQLMap, Prepared Statements, CSRF Protection
	Author: Muhammad Hamza Naseer
*/

const express=require("express");
const sqlite3=require("sqlite3").verbose();
const helmet=require("helmet");
const rateLimit=require("express-rate-limit");
const session=require("express-session");
const csrf=require("csurf");
const fs=require("fs");
const path=require("path");
const crypto=require("crypto");

const app=express();
const PORT=3005;

const publicDir=path.join(__dirname,"public");
const dataDir=path.join(__dirname,"data");

if(!fs.existsSync(dataDir)){
	fs.mkdirSync(dataDir);
}

app.use(express.json());
app.use(express.urlencoded({extended:false}));

app.use(session({
	secret:"week5_csrf_session_secret_2026",
	resave:false,
	saveUninitialized:true,
	cookie:{
		httpOnly:true,
		sameSite:"lax"
	}
}));

app.use((req,res,next)=>{
	if(!req.session.profile){
		req.session.profile={
			username:"admin",
			email:"admin@demo.local",
			role:"administrator"
		};
	}
	next();
});

app.use((req,res,next)=>{
	res.locals.nonce=crypto.randomBytes(16).toString("base64");
	next();
});

app.use(helmet({
	contentSecurityPolicy:{
		useDefaults:true,
		directives:{
			"default-src":["'self'"],
			"script-src":["'self'",(req,res)=>`'nonce-${res.locals.nonce}'`],
			"style-src":["'self'",(req,res)=>`'nonce-${res.locals.nonce}'`],
			"img-src":["'self'","data:"],
			"connect-src":["'self'"],
			"object-src":["'none'"],
			"frame-ancestors":["'none'"],
			"base-uri":["'self'"],
			"form-action":["'self'"],
			"script-src-attr":["'none'"]
		}
	},
	xFrameOptions:{
		action:"deny"
	},
	xContentTypeOptions:true,
	referrerPolicy:{
		policy:"no-referrer"
	}
}));

const limiter=rateLimit({
	windowMs:10*60*1000,
	max:80,
	standardHeaders:true,
	legacyHeaders:false,
	message:{
		error:"Too many requests. Slow down."
	}
});

app.use(limiter);

const db=new sqlite3.Database(path.join(dataDir,"week5_lab.db"));

db.serialize(()=>{
	db.run(`CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		email TEXT NOT NULL,
		password TEXT NOT NULL,
		role TEXT NOT NULL
	)`);

	db.run("DELETE FROM users");

	const insert=db.prepare("INSERT INTO users(username,email,password,role) VALUES(?,?,?,?)");

	insert.run("admin","admin@demo.local","Admin@12345","administrator");
	insert.run("hamza","hamza@student.local","Hamza@123","student");
	insert.run("sultan","sultan@student.local","Sultan@123","student");
	insert.run("guest","guest@demo.local","Guest@123","guest");

	insert.finalize();
});

const csrfProtection=csrf();

app.get("/",(req,res)=>{
	const indexPath=path.join(publicDir,"index.html");

	fs.readFile(indexPath,"utf8",(err,html)=>{
		if(err){
			return res.status(500).send("Frontend file missing.");
		}

		const finalHtml=html.split("{{NONCE}}").join(res.locals.nonce);
		res.type("html").send(finalHtml);
	});
});

app.get("/recon",(req,res)=>{
	res.json({
		app:"Week 5 Ethical Hacking Lab",
		environment:"Local test environment only",
		framework:"Node.js Express",
		database:"SQLite",
		endpoints:[
			"GET /vulnerable/user?id=1",
			"GET /secure/user?id=1",
			"POST /vulnerable/change-email",
			"GET /api/csrf-token",
			"POST /secure/change-email",
			"GET /api/profile"
		],
		securityTopics:[
			"Reconnaissance",
			"SQL Injection",
			"SQLMap Testing",
			"Prepared Statements",
			"CSRF Testing",
			"CSRF Protection"
		]
	});
});

app.get("/api/profile",(req,res)=>{
	res.json({
		message:"Current session profile",
		profile:req.session.profile
	});
});

/*
	VULNERABLE SQLi ROUTE
	This route is intentionally insecure for Week 5 testing.
*/
app.get("/vulnerable/user",(req,res)=>{
	const id=req.query.id||"1";
	const query=`SELECT id,username,email,role FROM users WHERE id=${id}`;

	db.all(query,(err,rows)=>{
		if(err){
			return res.status(500).json({
				mode:"vulnerable",
				error:err.message,
				query:query
			});
		}

		res.json({
			mode:"vulnerable",
			warning:"This endpoint is intentionally vulnerable to SQL injection.",
			query:query,
			rows:rows
		});
	});
});

/*
	SECURE SQLi MITIGATION ROUTE
	This route uses numeric validation and prepared statements.
*/
app.get("/secure/user",(req,res)=>{
	const id=Number(req.query.id);

	if(!Number.isInteger(id)){
		return res.status(400).json({
			mode:"secure",
			error:"Invalid ID. Only numeric integer IDs are allowed."
		});
	}

	const query="SELECT id,username,email,role FROM users WHERE id=?";

	db.get(query,[id],(err,row)=>{
		if(err){
			return res.status(500).json({
				mode:"secure",
				error:err.message
			});
		}

		if(!row){
			return res.status(404).json({
				mode:"secure",
				message:"No user found."
			});
		}

		res.json({
			mode:"secure",
			message:"Prepared statement used successfully.",
			query:query,
			row:row
		});
	});
});

/*
	VULNERABLE CSRF ROUTE
	This route changes email without CSRF token.
*/
app.post("/vulnerable/change-email",(req,res)=>{
	const email=req.body.email;

	if(!email){
		return res.status(400).json({
			mode:"vulnerable",
			error:"Email is required."
		});
	}

	req.session.profile.email=email;

	res.json({
		mode:"vulnerable",
		warning:"Email changed without CSRF protection.",
		profile:req.session.profile
	});
});

/*
	CSRF TOKEN ROUTE
	Frontend and Burp testing can fetch this token.
*/
app.get("/api/csrf-token",csrfProtection,(req,res)=>{
	res.json({
		csrfToken:req.csrfToken()
	});
});

/*
	SECURE CSRF ROUTE
	This route requires a valid CSRF token.
*/
app.post("/secure/change-email",csrfProtection,(req,res)=>{
	const email=req.body.email;

	if(!email){
		return res.status(400).json({
			mode:"secure",
			error:"Email is required."
		});
	}

	req.session.profile.email=email;

	res.json({
		mode:"secure",
		message:"Email changed successfully with valid CSRF token.",
		profile:req.session.profile
	});
});

app.use((err,req,res,next)=>{
	if(err.code==="EBADCSRFTOKEN"){
		return res.status(403).json({
			error:"CSRF token missing or invalid. Request blocked."
		});
	}

	res.status(500).json({
		error:"Internal server error",
		details:err.message
	});
});

app.listen(PORT,()=>{
	console.log(`Week 5 Ethical Hacking Lab running at http://localhost:${PORT}`);
	console.log("Vulnerable SQLi test: http://localhost:3005/vulnerable/user?id=1 OR 1=1");
	console.log("Secure SQLi test: http://localhost:3005/secure/user?id=1");
});
