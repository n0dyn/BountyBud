---
id: "source-code-review"
title: "Source Code Review for Bug Bounty - What to Hunt With Source Access"
type: "methodology"
category: "web-application"
subcategory: "code-review"
tags: ["code-review", "source-code", "hardcoded-secrets", "sql-injection", "command-injection", "deserialization", "auth-bypass", "sast", "deep-dig"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["javascript-analysis", "deserialization", "command-injection-payloads", "sqli-payloads"]
updated: "2026-04-14"
---

## Overview

Source code access (open-source targets, leaked repos, client-provided code) transforms bug bounty hunting from black-box guessing to surgical exploitation. You know exactly where input enters, how it flows, and where it hits dangerous sinks. GitGuardian's 2025 report found 23.8 million secrets exposed on GitHub (25% YoY increase). Code review finds bugs that scanners miss: business logic flaws, race conditions, and subtle auth bypasses.

## Phase 1: Reconnaissance & Triage

### Get oriented
```bash
# Understand the codebase
wc -l $(find . -name "*.py" -o -name "*.js" -o -name "*.java" -o -name "*.rb" -o -name "*.php" -o -name "*.go") | tail -1
# Lines of code tells you the scope

# Find the entry points (routes/controllers)
grep -rn "app.get\|app.post\|@app.route\|@RequestMapping\|Route::" --include="*.py" --include="*.js" --include="*.java" --include="*.rb" --include="*.php" --include="*.go" .

# Find authentication middleware
grep -rn "authenticate\|authorize\|isAdmin\|requireAuth\|@login_required\|before_action\|middleware" .

# Find the data model
grep -rn "CREATE TABLE\|Schema(\|class.*Model\|@Entity\|has_many\|belongs_to" .

# Check for security configurations
find . -name "*.yml" -o -name "*.yaml" -o -name "*.toml" -o -name "*.ini" -o -name "*.conf" | head -20
```

### Priority triage
```
HIGH PRIORITY (check first):
1. Authentication / authorization logic
2. Payment / financial operations  
3. File upload / download handlers
4. Admin / privileged functionality
5. User input → database queries
6. User input → OS commands
7. Deserialization of user data
8. Cryptographic operations

MEDIUM PRIORITY:
9. Session management
10. Email sending (SMTP injection, template injection)
11. API integrations (SSRF via URL params)
12. Logging (sensitive data in logs)
13. Error handling (info disclosure)
14. Rate limiting implementation

LOW PRIORITY (but still valuable):
15. CORS configuration
16. CSP headers
17. Cookie settings
18. Dependency versions
```

## Phase 2: Hardcoded Secrets

### Automated scanning
```bash
# Trufflehog (scans git history too)
trufflehog git file://. --only-verified

# Gitleaks
gitleaks detect -v

# Semgrep for secrets
semgrep --config "p/secrets" .

# Manual patterns
grep -rn "password\s*=\s*[\"']" --include="*.py" --include="*.js" --include="*.java" .
grep -rn "AKIA[A-Z0-9]{16}" .  # AWS access keys
grep -rn "sk_live_[a-zA-Z0-9]+" .  # Stripe secret keys
grep -rn "ghp_[a-zA-Z0-9]{36}" .  # GitHub PATs
grep -rn "xox[bpsa]-[a-zA-Z0-9-]+" .  # Slack tokens
grep -rn "SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}" .  # SendGrid
grep -rn "AIza[0-9A-Za-z_-]{35}" .  # Google API keys
grep -rn "-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----" .
grep -rn "mongodb://\|postgres://\|mysql://\|redis://" .  # DB connection strings
```

### Git history secrets
```bash
# Check all commits for secrets
git log --all --diff-filter=D -- "*.env" "*.key" "*.pem"
git log --all -p -- "*.env" | grep -E "(SECRET|KEY|PASSWORD|TOKEN)="

# Find deleted files with secrets
git log --all --full-history -- "*secret*" "*credential*" "*.env" "*config*"
git show COMMIT_HASH:path/to/deleted/.env

# Check for force-pushed (rewritten) commits
git reflog | head -50
```

## Phase 3: SQL Injection Sources

### Pattern matching
```bash
# Direct string concatenation (DANGEROUS)
# Python
grep -rn "execute.*%s\|execute.*format\|execute.*f'" --include="*.py" .
grep -rn "cursor.execute.*+\|cursor.execute.*%\|cursor.execute.*\.format" --include="*.py" .

# Java
grep -rn "createQuery.*+\|executeQuery.*+\|Statement.*execute" --include="*.java" .
grep -rn "nativeQuery.*true" --include="*.java" .  # JPA native queries

# PHP
grep -rn "\$.*query.*\\\$\|mysql_query.*\\\$\|mysqli.*query.*\\\$" --include="*.php" .
grep -rn "->where.*raw\|DB::raw\|whereRaw\|selectRaw" --include="*.php" .  # Laravel

# Node.js
grep -rn "query.*\`\|query.*+\|\.raw(" --include="*.js" --include="*.ts" .

# Ruby
grep -rn "where.*#{\|find_by_sql.*#{\|execute.*#{\|\.order.*params" --include="*.rb" .

# Go
grep -rn "fmt.Sprintf.*SELECT\|fmt.Sprintf.*INSERT\|Exec.*+\|Query.*+" --include="*.go" .
```

### ORM bypass patterns
```
# Even ORMs can be vulnerable:
# Django: .extra(), .raw(), RawSQL()
grep -rn "\.extra(\|\.raw(\|RawSQL(" --include="*.py" .

# SQLAlchemy: text(), from_statement()
grep -rn "text(\|from_statement(" --include="*.py" .

# ActiveRecord: find_by_sql, where with string
grep -rn "find_by_sql\|\.where(\"" --include="*.rb" .

# Sequelize: literal(), query()
grep -rn "sequelize.literal\|sequelize.query" --include="*.js" --include="*.ts" .
```

## Phase 4: Command Injection Sources

```bash
# Python
grep -rn "os.system\|os.popen\|subprocess.call\|subprocess.Popen\|subprocess.run" --include="*.py" .
grep -rn "eval(\|exec(\|compile(" --include="*.py" .  # Code execution

# Java
grep -rn "Runtime.getRuntime().exec\|ProcessBuilder\|ScriptEngine" --include="*.java" .

# PHP
grep -rn "system(\|exec(\|shell_exec(\|passthru(\|popen(\|proc_open(" --include="*.php" .
grep -rn "eval(\|assert(\|preg_replace.*\/e" --include="*.php" .

# Node.js
grep -rn "child_process\|exec(\|execSync\|spawn(" --include="*.js" --include="*.ts" .
grep -rn "eval(\|Function(\|vm\.run\|vm\.createContext" --include="*.js" --include="*.ts" .

# Ruby
grep -rn "system(\|exec(\|\`.*#{\|%x(\|IO.popen\|Open3" --include="*.rb" .

# Go
grep -rn "exec.Command\|os.StartProcess" --include="*.go" .

# Trace from user input to these sinks
# Key: does user input reach these functions without sanitization?
```

## Phase 5: Deserialization Sinks

```bash
# Java
grep -rn "ObjectInputStream\|readObject\|readUnshared\|XMLDecoder\|XStream" --include="*.java" .
grep -rn "fromJson\|ObjectMapper.*readValue\|@JsonTypeInfo" --include="*.java" .
# Check for known gadget chain libraries in pom.xml/build.gradle:
# commons-collections, commons-beanutils, spring-core

# Python
grep -rn "pickle.load\|pickle.loads\|cPickle\|shelve\|marshal.load\|yaml.load\|yaml.unsafe_load" --include="*.py" .
# yaml.load without Loader=SafeLoader is vulnerable

# PHP
grep -rn "unserialize(\|deserialize(" --include="*.php" .
# Check if __wakeup, __destruct, __toString exist in classes

# Ruby
grep -rn "Marshal.load\|YAML.load\|JSON.parse.*create_additions" --include="*.rb" .

# Node.js
grep -rn "serialize(\|unserialize(\|node-serialize\|funcster" --include="*.js" --include="*.ts" .
# Also check: js-yaml (dangerous schemas), cryo

# .NET
grep -rn "BinaryFormatter\|XmlSerializer\|JavaScriptSerializer\|Json.Net.*TypeNameHandling\|DataContractSerializer" --include="*.cs" .
```

## Phase 6: Authentication & Authorization Review

### Auth bypass patterns
```bash
# Missing auth checks
# Find routes/endpoints WITHOUT auth middleware
# Compare route definitions with middleware assignments

# Inconsistent auth (some endpoints protected, others not)
grep -rn "@login_required\|@require_auth\|authenticate\|isAuthenticated" --include="*.py" --include="*.js" --include="*.rb" .
# Cross-reference with ALL route definitions

# Role check flaws
grep -rn "role\s*==\|isAdmin\|is_admin\|user\.role\|currentUser\.admin" .
# Check: is role from JWT (modifiable)? From session? From DB?

# IDOR patterns
grep -rn "params\[:id\]\|req.params.id\|request.args.get.*id\|@PathVariable" .
# For each: is the ID validated against the authenticated user?

# Horizontal privilege escalation
# user.id vs params.user_id — are they compared?
grep -rn "user_id\|userId\|owner_id\|author_id" .
```

### Session management review
```bash
# Session configuration
grep -rn "session.*secret\|SESSION_SECRET\|cookie.*secure\|httponly\|samesite" .
# Check entropy of session IDs (custom generation?)
# Check session storage (files, DB, Redis, memory?)

# Token generation
grep -rn "generate.*token\|create.*token\|random.*hex\|uuid\|crypto.random" .
# Is it using crypto-secure random? Or Math.random()?
```

## Phase 7: Dangerous Patterns by Framework

### Django (Python)
```python
# DANGEROUS
HttpResponse(user_input)  # XSS if not escaped
cursor.execute("SELECT * FROM users WHERE id=" + user_id)  # SQLi
mark_safe(user_data)  # Explicitly bypasses escaping
|safe  # In templates: {{ user_data|safe }}
```

### Rails (Ruby)
```ruby
# DANGEROUS
.html_safe  # Bypasses escaping
raw(user_input)  # No escaping
render inline: user_input  # Template injection
where("name = '#{params[:name]}'")  # SQLi
send(params[:method])  # Arbitrary method call
```

### Express/Node.js
```javascript
// DANGEROUS
res.send(userInput)  // XSS if HTML
eval(req.body.code)  // RCE
require(userInput)  // Arbitrary module load
child_process.exec(cmd + userInput)  // Command injection
new Function(userInput)  // Code execution
```

### Spring (Java)
```java
// DANGEROUS
@ResponseBody + string concat with user input  // XSS
nativeQuery = true with string concat  // SQLi
Runtime.getRuntime().exec(userInput)  // RCE
new ObjectInputStream(userControlledStream)  // Deserialization
redirect:"+ userInput  // Open redirect
```

### Laravel (PHP)
```php
// DANGEROUS
{!! $userInput !!}  // Unescaped output (XSS)
DB::raw($userInput)  // SQLi
eval($userInput)  // RCE
unserialize($userInput)  // Deserialization
header("Location: " . $userInput)  // Open redirect, CRLF
```

## Phase 8: Dependency Analysis

```bash
# Find vulnerable dependencies
# Python
pip-audit
safety check -r requirements.txt

# Node.js
npm audit
snyk test

# Java
mvn dependency-check:check  # OWASP Dependency-Check

# Ruby
bundle-audit check

# Go
govulncheck ./...

# Check for known vulnerable versions
# Log4j (Java): log4j-core < 2.17.1
# Jackson (Java): jackson-databind with polymorphic type handling
# Lodash (JS): < 4.17.21 (prototype pollution)
# jQuery (JS): < 3.5.0 (XSS)
# Django (Python): check against security releases
```

## Automated SAST Tools

```bash
# Semgrep (multi-language, fast, free rules)
semgrep --config auto .
semgrep --config "p/owasp-top-ten" .
semgrep --config "p/security-audit" .

# CodeQL (GitHub-integrated)
codeql database create mydb --language=javascript
codeql database analyze mydb javascript-security-and-quality.qls

# Bandit (Python)
bandit -r . -ll

# Brakeman (Ruby/Rails)
brakeman .

# NodeJSScan (Node.js)
nodejsscan -d .

# SpotBugs + FindSecBugs (Java)
mvn com.github.spotbugs:spotbugs-maven-plugin:spotbugs
```

## Code Review Checklist

```
SECRETS:
[ ] No hardcoded API keys, passwords, tokens
[ ] No secrets in git history
[ ] .env files in .gitignore
[ ] Secrets loaded from environment/vault

INJECTION:
[ ] All SQL uses parameterized queries (no string concat)
[ ] No OS command execution with user input
[ ] Template rendering uses auto-escaping
[ ] No eval/exec/Function with user data

DESERIALIZATION:
[ ] No unsafe deserialization of user-controlled data
[ ] Type checking before deserialization
[ ] Allowlist of deserializable classes (Java)

AUTH:
[ ] All sensitive routes have auth middleware
[ ] Authorization checks use server-side session (not JWT claims alone)
[ ] Password hashing uses bcrypt/argon2 (not MD5/SHA1)
[ ] Session tokens are crypto-random

BUSINESS LOGIC:
[ ] Race conditions handled (locks, transactions)
[ ] Price/quantity validation server-side
[ ] Rate limiting on sensitive operations
[ ] Multi-step processes validated server-side
```

## Tools

- **Semgrep** -- Multi-language SAST (custom rules)
- **CodeQL** -- Deep semantic code analysis
- **Trufflehog** -- Git history secret scanning
- **Gitleaks** -- Secret detection in code
- **Bandit** -- Python SAST
- **Brakeman** -- Ruby/Rails SAST
- **NodeJSScan** -- Node.js security scanner
- **SpotBugs + FindSecBugs** -- Java SAST
- **pip-audit / npm audit / snyk** -- Dependency vulnerability scanning
