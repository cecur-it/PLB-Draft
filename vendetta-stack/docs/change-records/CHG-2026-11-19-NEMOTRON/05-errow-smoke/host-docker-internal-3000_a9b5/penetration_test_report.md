# Security Penetration Test Report

**Generated:** 2026-11-19 10:38:07 UTC

# Executive Summary

**Executive Summary**  
The assessment of the OWASP Juice Shop instance at `http://host.docker.internal:3000` identified three high‑impact vulnerabilities. An unauthenticated SQL injection in the product‑search endpoint exposed the full product catalogue, while a second injection in the login endpoint enabled complete authentication bypass, granting an attacker a valid admin JWT. Additionally, a path‑traversal flaw in the FTP directory listing allowed retrieval of sensitive backup files, including `package.json.bak`. All findings have been validated with proof‑of‑concept requests and assigned CVSS scores of 9.1 (critical) and 7.5 (high). The combined impact represents a severe risk of data disclosure, privilege escalation, and potential further exploitation within the application. Immediate remediation—parameterised queries, input validation, and proper path sanitisation—is recommended to mitigate these critical weaknesses.

# Methodology

OWASP WSTG methodology was applied, encompassing reconnaissance, static and dynamic analysis, vulnerability validation, and reporting. The assessment followed a black‑box approach, focusing on externally observable endpoints without prior source‑code knowledge.

# Technical Analysis

The three findings stem from insufficient input sanitisation in distinct components of the application: (1) the product‑search query builder reflects the `q` parameter directly into an SQLite statement, allowing boolean‑based injection; (2) the authentication service concatenates the `email` field into a dynamic SQL query, enabling credential‑independent JWT issuance; (3) the FTP endpoint resolves directory paths to filesystem locations without null‑byte or traversal validation, exposing arbitrary file contents. In each case, the attacker can achieve impact beyond the intended scope—enumerating data, bypassing authentication, and reading sensitive configuration files—without requiring authentication or privileged access.

# Recommendations

**Immediate**  
1. Refactor all query constructions to use parameterised statements or ORM‑level bindings.  
2. Implement strict allow‑list validation for any parameter that influences file‑system paths.  

**Short‑term**  
3. Deploy a Web Application Firewall (WAF) with rules targeting SQL‑injection patterns and path‑traversal attempts.  
4. Conduct a code‑review of all dynamic query sites to enforce defensive coding practices.  

**Medium‑term**  
5. Introduce automated static analysis (e.g., semgrep) into the CI pipeline to detect unsafe query patterns before deployment.  
6. Rotate and protect backup files, ensuring they are stored outside the web‑root and not served by the application.  

These actions collectively reduce the attack surface, raise the cost of exploitation, and align the application with secure coding standards.

