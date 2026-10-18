# VEYRON Assessment Report — Example

> **Note:** This is a verbatim report produced by running eyron scan fixtures/vulnerable_app
> against the bundled deliberately-vulnerable test fixture. Absolute paths have been relativised
> and the interpreter path shortened; all findings, evidence, severities, and tool versions are
> exactly as emitted. No live or third-party target was scanned.


- **Target:** `fixtures/vulnerable_app`
- **Assessment ID:** `654d4edaa3b4`
- **Generated:** 2026-10-18T09:42:46+00:00
- **VEYRON version:** 0.1.0
- **AI-assisted analysis:** enabled

## 1. Executive summary

**11 finding(s)** normalised from all sources.

| Severity | Count |
|---|---|
| High | 2 |
| Medium | 6 |
| Low | 3 |

> ⚠ **Coverage warning:** Scanner(s) failed and did not complete: osv. Absence of findings from these scanners is NOT evidence of a clean result. Some file types were not analysed: .json, .txt.

## 2. Scope

- Files assessed: **5** (1701 bytes)
- Excluded directories: none
- Skipped files: 0
- Unsupported extensions: .json, .txt
- Notes:
  - Assessment scope: files under fixtures/vulnerable_app after configured exclusions.
  - Repository scripts were not executed during discovery.

## 3. Tools and versions

| Scanner | Status | Version | Duration (s) | Failure reason |
|---|---|---|---|---|
| semgrep | ✅ ok | 1.181.0 | 8.1 | - |
| bandit | ✅ ok | bandit 1.9.4 | 0.6 | - |
| gitleaks | ✅ ok | 8.30.1 | 0.8 | - |
| osv | ❌ FAILED | n/a | 0.0 | OSV adapter offline but no advisory cache available |

## 4. Findings

### 1. Use of weak MD5 hash for security. Consider usedforsecurity=False

- **ID:** `VYN-CFB38C6248DA`  
- **Severity:** HIGH | **Confidence:** HIGH | **State:** DETECTED | **Priority score:** 6.0
- **Source:** `sast.bandit` (tool: bandit, rule: `B324`)
- **Location:** `fixtures/vulnerable_app\app.py` line 31

Use of weak MD5 hash for security. Consider usedforsecurity=False

**Evidence**

```
rule=B324
30 
31     return hashlib.md5(password.encode()).hexdigest()
32
```

**Remediation:** https://bandit.readthedocs.io/en/1.9.4/plugins/b324_hashlib.html

**Prioritisation assumptions:**
- Validation status DETECTED; score discounted pending evidence.

### 2. Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy prov

- **ID:** `VYN-B167E9A87045`  
- **Severity:** HIGH | **Confidence:** MEDIUM | **State:** DETECTED | **Priority score:** 5.1
- **Source:** `sast.semgrep` (tool: semgrep, rule: `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`)
- **Location:** `fixtures/vulnerable_app\app.py` line 18
- **Advisories:** https://docs.sqlalchemy.org/en/14/core/tutorial.html#using-textual-sql, https://www.tutorialspoint.com/sqlalchemy/sqlalchemy_quick_guide.htm, https://docs.sqlalchemy.org/en/14/core/tutorial.html#using-more-specific-text-with-table-expression-literal-column-and-expression-column

Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option.

**Evidence**

```
rule=python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
requires login
```

**Prioritisation assumptions:**
- Validation status DETECTED; score discounted pending evidence.

### 3. Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

- **ID:** `VYN-6246432FFB41`  
- **Severity:** MEDIUM | **Confidence:** HIGH | **State:** DETECTED | **Priority score:** 4.0
- **Source:** `sast.bandit` (tool: bandit, rule: `B301`)
- **Location:** `fixtures/vulnerable_app\app.py` line 38

Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**Evidence**

```
rule=B301
37 
38     return pickle.loads(data)
39
```

**Remediation:** https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_calls.html#b301-pickle

**Prioritisation assumptions:**
- Validation status DETECTED; score discounted pending evidence.

### 4. Use of possibly insecure function - consider using safer ast.literal_eval.

- **ID:** `VYN-67700364655D`  
- **Severity:** MEDIUM | **Confidence:** HIGH | **State:** DETECTED | **Priority score:** 4.0
- **Source:** `sast.bandit` (tool: bandit, rule: `B307`)
- **Location:** `fixtures/vulnerable_app\app.py` line 24

Use of possibly insecure function - consider using safer ast.literal_eval.

**Evidence**

```
rule=B307
23     """VULNERABLE ON PURPOSE: evaluating untrusted input (CWE-95)."""
24     return eval(user_input)
25
```

**Remediation:** https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_calls.html#b307-eval

**Prioritisation assumptions:**
- Validation status DETECTED; score discounted pending evidence.

### 5. Avoid using `pickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider serializing the relev

- **ID:** `VYN-0BD2CEFBC3DF`  
- **Severity:** MEDIUM | **Confidence:** MEDIUM | **State:** DETECTED | **Priority score:** 3.4
- **Source:** `sast.semgrep` (tool: semgrep, rule: `python.lang.security.deserialization.pickle.avoid-pickle`)
- **Location:** `fixtures/vulnerable_app\app.py` line 38
- **Advisories:** https://docs.python.org/3/library/pickle.html

Avoid using `pickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider serializing the relevant data as JSON or a similar text-based serialization format.

**Evidence**

```
rule=python.lang.security.deserialization.pickle.avoid-pickle
requires login
```

**Prioritisation assumptions:**
- Validation status DETECTED; score discounted pending evidence.

### 6. It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function 

- **ID:** `VYN-1EABC714F2C6`  
- **Severity:** MEDIUM | **Confidence:** MEDIUM | **State:** DETECTED | **Priority score:** 3.4
- **Source:** `sast.semgrep` (tool: semgrep, rule: `python.lang.security.audit.md5-used-as-password.md5-used-as-password`)
- **Location:** `fixtures/vulnerable_app\app.py` line 31
- **Advisories:** https://tools.ietf.org/html/rfc6151, https://crypto.stackexchange.com/questions/44151/how-does-the-flame-malware-take-advantage-of-md5-collision, https://pycryptodome.readthedocs.io/en/latest/src/hash/sha3_256.html, https://security.stackexchange.com/questions/211/how-to-securely-hash-passwords, https://github.com/returntocorp/semgrep-rules/issues/1609, https://docs.python.org/3/library/hashlib.html#hashlib.scrypt

It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function such as scrypt. You can use `hashlib.scrypt`.

**Evidence**

```
rule=python.lang.security.audit.md5-used-as-password.md5-used-as-password
requires login
```

**Prioritisation assumptions:**
- Validation status DETECTED; score discounted pending evidence.

### 7. Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evalu

- **ID:** `VYN-3121B5C5B21F`  
- **Severity:** MEDIUM | **Confidence:** MEDIUM | **State:** DETECTED | **Priority score:** 3.4
- **Source:** `sast.semgrep` (tool: semgrep, rule: `python.lang.security.audit.eval-detected.eval-detected`)
- **Location:** `fixtures/vulnerable_app\app.py` line 24
- **Advisories:** https://owasp.org/Top10/A03_2021-Injection

Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.

**Evidence**

```
rule=python.lang.security.audit.eval-detected.eval-detected
requires login
```

**Prioritisation assumptions:**
- Validation status DETECTED; score discounted pending evidence.

### 8. Possible SQL injection vector through string-based query construction.

- **ID:** `VYN-EC431ACF452F`  
- **Severity:** MEDIUM | **Confidence:** MEDIUM | **State:** DETECTED | **Priority score:** 3.4
- **Source:** `sast.bandit` (tool: bandit, rule: `B608`)
- **Location:** `fixtures/vulnerable_app\app.py` line 18

Possible SQL injection vector through string-based query construction.

**Evidence**

```
rule=B608
17     cursor = conn.cursor()
18     cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))
19     return cursor.fetchall()
```

**Remediation:** https://bandit.readthedocs.io/en/1.9.4/plugins/b608_hardcoded_sql_expressions.html

**Prioritisation assumptions:**
- Validation status DETECTED; score discounted pending evidence.

### 9. Consider possible security implications associated with pickle module.

- **ID:** `VYN-DDFC6823C728`  
- **Severity:** LOW | **Confidence:** HIGH | **State:** DETECTED | **Priority score:** 2.0
- **Source:** `sast.bandit` (tool: bandit, rule: `B403`)
- **Location:** `fixtures/vulnerable_app\app.py` line 36

Consider possible security implications associated with pickle module.

**Evidence**

```
rule=B403
35     """VULNERABLE ON PURPOSE: pickle loads on untrusted data (CWE-502)."""
36     import pickle
37
```

**Remediation:** https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b403-import-pickle

**Prioritisation assumptions:**
- Validation status DETECTED; score discounted pending evidence.

### 10. Possible hardcoded password: 'fake-password-not-real-000111'

- **ID:** `VYN-B98D8917542A`  
- **Severity:** LOW | **Confidence:** MEDIUM | **State:** DETECTED | **Priority score:** 1.7
- **Source:** `sast.bandit` (tool: bandit, rule: `B105`)
- **Location:** `fixtures/vulnerable_app\app.py` line 43

Possible hardcoded password: '[REDACTED]'

**Evidence**

```
rule=B105
42 FAKE_API_KEY = "FAKE_API_KEY_FOR_TESTS_1234567890abcdef"
43 FAKE_PASSWORD = "fake-password-not-real-000111"
```

**Remediation:** https://bandit.readthedocs.io/en/1.9.4/plugins/b105_hardcoded_password_string.html

**Prioritisation assumptions:**
- Validation status DETECTED; score discounted pending evidence.

### 11. Possible hardcoded password: 'fake-password-not-real-000111'

- **ID:** `VYN-FB012BEC960E`  
- **Severity:** LOW | **Confidence:** MEDIUM | **State:** DETECTED | **Priority score:** 1.7
- **Source:** `sast.bandit` (tool: bandit, rule: `B105`)
- **Location:** `fixtures/vulnerable_app\config_dev.py` line 3

Possible hardcoded password: '[REDACTED]'

**Evidence**

```
rule=B105
2 api_key = "[REDACTED]"
3 password = "[REDACTED]"
3 password = "fake-password-not-real-000111"
3 password = "[REDACTED]"
```

**Remediation:** https://bandit.readthedocs.io/en/1.9.4/plugins/b105_hardcoded_password_string.html

**Prioritisation assumptions:**
- Validation status DETECTED; score discounted pending evidence.

## 5. Validation status distribution

| State | Count |
|---|---|
| DETECTED | 11 |

## 6. Known limitations

- Static analysis cannot establish exploitability; findings are candidates until validated.
- Dependency advisories indicate affected version ranges, not confirmed exploitability in this application.
- Scanner 'osv': OSV adapter offline but no advisory cache available (missing_executable).
- Unsupported file types were excluded from analysis; coverage is not complete.

---
_Generated by VEYRON v0.1.0 — evidence over speculation._
