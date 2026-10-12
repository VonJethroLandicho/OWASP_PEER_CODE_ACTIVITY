# Vulnerability Findings — Von Jethro E. Landicho & Christian Joshua Manaog

There are **6** security bugs planted in `app/main.py`. Fill one row per bug.

| # | OWASP 2025 code & name         | Where (route / line)                    | How an attacker abuses it                                                       | Your fix (1 line)                                                              |
|---|--------------------------------|-----------------------------------------|---------------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| 1 | A01: Broken Access Control     | /notes/{note_id} (lines 132-139)        | Modifies note ID in URL to view another user's private notes (IDOR)             | Verify requested note owner matches user["id"], else return 403 Forbidden      |
| 2 | A02: Security Misconfiguration | Config & Handler (lines 25, 29, 94-99)  | Wildcard CORS (*), hardcoded secret key, and stack traces on 500 leak internals | Restrict CORS origins, load secret from env var, and return generic 500 error  |
| 3 | A04: Cryptographic Failures    | Seed & /register (lines 63-65, 105-109) | Passwords stored in plaintext; database breach exposes all user credentials     | Hash passwords with salt using PBKDF2; verify via hmac.compare_digest          |
| 4 | A05: Injection                 | /login (lines 115-117)                  | Injects SQL via username (e.g. ' OR 1=1 --) to bypass auth without password     | Use parameterized query (WHERE username = ?) with parameter tuple, no f-string |
| 5 | A07: Authentication Failures   | Auth & /login (lines 86-90, 118-122)    | Sequential integer tokens allow hijacking; login leaks valid usernames          | Issue signed expiring HMAC-SHA256 tokens; return uniform 401 on bad login      |
| 6 | A10: Exceptional Conditions    | /admin/users (lines 153-161)            | Admin check catches exceptions and silently passes, allowing access (fail-open) | Fail closed: check if not user["is_admin"] and raise 403 Forbidden             |

## Reflection (3–4 sentences)
Which bug would do the most damage in a real app, and why?

In a real-world application, **A05: Injection (SQL Injection)** causes the most catastrophic damage because it grants attackers direct control over the database engine. Through SQL injection, an unauthenticated attacker can bypass login mechanisms, exfiltrate the entire database (including user credentials and private notes), and even tamper with or drop tables. While access control and configuration flaws allow unauthorized access to specific resources, SQL injection completely compromises confidentiality, integrity, and availability in a single step.

