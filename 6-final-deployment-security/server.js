/*
	Week 6 Final Deployment Security
	Advanced Security Audits & Secure Deployment
	Author: Muhammad Hamza Naseer
*/

const express=require("express");
const helmet=require("helmet");
const cors=require("cors");
const rateLimit=require("express-rate-limit");
const path=require("path");
const fs=require("fs");
const crypto=require("crypto");
require("dotenv").config();

const app=express();
const PORT=process.env.PORT||4006;

app.disable("x-powered-by");

app.use(express.json({limit:"10kb"}));
app.use(express.urlencoded({extended:false,limit:"10kb"}));

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
	},
	crossOriginResourcePolicy:{
		policy:"same-origin"
	}
}));

app.use(cors({
	origin:["http://localhost:4006","http://127.0.0.1:4006"],
	methods:["GET","POST"],
	allowedHeaders:["Content-Type"],
	credentials:false
}));

const limiter=rateLimit({
	windowMs:15*60*1000,
	max:100,
	standardHeaders:true,
	legacyHeaders:false,
	message:{
		error:"Too many requests. Please slow down."
	}
});

app.use(limiter);

app.get("/",(req,res)=>{
	const indexPath=path.join(__dirname,"public","index.html");

	fs.readFile(indexPath,"utf8",(err,html)=>{
		if(err){
			return res.status(500).send("Frontend not found.");
		}

		const finalHtml=html.split("{{NONCE}}").join(res.locals.nonce);
		res.type("html").send(finalHtml);
	});
});

app.get("/health",(req,res)=>{
	res.json({
		status:"healthy",
		service:"week6-final-deployment-security",
		security:"enabled"
	});
});

app.get("/api/security-checklist",(req,res)=>{
	res.json({
		owaspTop10:{
			brokenAccessControl:"Reviewed",
			cryptographicFailures:"Secure headers and safe configuration applied",
			injection:"No raw SQL used in final deployment app",
			insecureDesign:"Security-first design followed",
			securityMisconfiguration:"Helmet, CORS, rate limiting and x-powered-by disabled",
			vulnerableComponents:"Checked using npm audit",
			authenticationFailures:"Rate limiting enabled",
			softwareDataIntegrity:"Dependencies scanned",
			loggingMonitoring:"Audit testing performed",
			ssrf:"No server-side URL fetch functionality"
		},
		deploymentSecurity:[
			"Dockerfile created",
			"Non-root container user configured",
			"node_modules ignored from upload",
			"Sensitive files ignored",
			"Dependency scanning planned",
			"Container image scanning planned",
			"OWASP ZAP scan planned",
			"Nikto scan planned",
			"Lynis system audit planned"
		]
	});
});

app.post("/api/contact",(req,res)=>{
	const {name,message}=req.body;

	if(!name||!message){
		return res.status(400).json({
			error:"Name and message are required."
		});
	}

	if(name.length>50||message.length>300){
		return res.status(400).json({
			error:"Input length exceeded."
		});
	}

	res.json({
		message:"Input accepted safely.",
		received:{
			name:name,
			message:message
		}
	});
});

app.use((req,res)=>{
	res.status(404).json({
		error:"Route not found"
	});
});

app.use((err,req,res,next)=>{
	res.status(500).json({
		error:"Internal server error"
	});
});

app.listen(PORT,()=>{
	console.log(`Week 6 Final Secure Deployment running at http://localhost:${PORT}`);
});
