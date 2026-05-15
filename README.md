# Web Application Security Assessment & Remediation
**Developershub Cybersecurity Internship Task (Weeks 1-3)**

## Project Overview
This repository contains the progression of a Node.js/SQLite User Management System, demonstrating the identification of critical web vulnerabilities and their subsequent Enterprise-grade remediations.

### 📁 1-vulnerable-app (Week 1 Baseline)
This directory contains the baseline application intentionally built with critical security flaws. During the penetration testing phase, the following vulnerabilities were exploited:
* **SQL Injection (SQLi):** Authentication bypass and data extraction via the `/login` route.
* **Reflected XSS:** Arbitrary script execution via the `/profile` route.
* **Insecure Storage:** Passwords stored in plaintext.

### 📁 2-secure-app (Weeks 2 & 3 Enterprise Remediation)
This directory contains the hardened application. The following security measures were implemented to patch the baseline vulnerabilities and satisfy advanced auditing requirements:
* **Parameterized Queries:** Neutralized SQLi payloads.
* **Input Sanitization:** Implemented `validator` to safely escape inputs and prevent XSS.
* **Cryptographic Hashing:** Integrated `bcrypt` (12 salt rounds) for secure password storage.
* **Strict Security Headers:** Deployed `helmet` with a strict Content Security Policy (CSP) and Anti-clickjacking headers.
* **Brute-Force Protection:** Implemented `express-rate-limit` to block credential stuffing and DoS attempts (Max 5 requests / 15 mins).
* **JWT Authentication:** Replaced stateful login checks with stateless token verification.
* **Advanced Security Auditing:** Integrated `winston` logging framework to persistently track authentication events, database errors, and rate-limit triggers in a `security-audit.log` file.

## How to Run
Navigate to either directory, install the dependencies, and start the server:
\`\`\`bash
npm install
node server.js
\`\`\`
