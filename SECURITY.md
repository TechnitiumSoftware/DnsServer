# Security Policy

## Supported Versions

Only the latest available version of Technitium DNS Server is supported for security updates.

## Reporting a Vulnerability

### Form of Communication (Recommendation 1)

To report a vulnerability, send an email to **security@technitium.com** with:
- **Subject line**: `[SECURITY] Vulnerability Report - [Brief Description]`
- **Encryption**: For sensitive disclosures, request our PGP key in your initial contact
- **Language**: Reports in English are preferred

### Confidentiality Request

We kindly request that you:
- **Do not disclose** the vulnerability to third parties until we have issued a fix
- **Do not publish** details publicly until coordinated disclosure is agreed upon
- Maintain confidentiality during our investigation and remediation process

### Legal Authorization for Security Research

Technitium Software authorizes good-faith security research on Technitium DNS Server under the following conditions:
- Testing is performed on your own systems or with explicit permission
- You make a good faith effort to avoid privacy violations, data destruction, and service disruption
- You provide us a reasonable time to address the vulnerability before public disclosure

**Safe Harbor**: We will not pursue legal action against researchers who comply with this policy.

### Expected Timeline and Process

| Phase | Timeline |
|-------|----------|
| **Initial Acknowledgment** | Within 5 business days |
| **Status Updates** | Every 7-14 days until resolved |
| **Preliminary Assessment** | Within 14 days |
| **Fix Development** | Varies by severity (communicated upon assessment) |
| **Coordinated Disclosure** | Mutually agreed upon, typically 90 days from report |

**Process Description**:
1. You submit a vulnerability report
2. We acknowledge receipt and assign a tracking identifier
3. We investigate and assess severity
4. We develop and test a fix
5. We release a patched version
6. We coordinate public disclosure with you

We will keep you informed of the vulnerability's status and remediation progress throughout this process.

### Bug Bounty Program

We **do not currently offer a bug bounty program** or monetary rewards. However, we deeply appreciate responsible disclosure and will:
- Acknowledge your contribution in our security advisories (with your permission)
- Provide public credit for your discovery (if desired)

### Expected Form of Report

Please include the following in your vulnerability report:

**Required**:
- **Impact**: What is the security impact? (e.g., remote code execution, information disclosure, authentication bypass)
- **Steps to Reproduce**: Detailed steps to reproduce the vulnerability
- **Affected Versions**: Which version(s) are impacted?
- **Proof of Concept**: Sample code or commands demonstrating the issue (if applicable)

**Optional but Appreciated**:
- **Root Cause Analysis**: Technical analysis of why the vulnerability exists
- **Suggested Fix**: Your recommendations for remediation
- **CVSSv3 Score**: Your severity assessment
- **Screenshots/Videos**: Visual evidence of exploitation

**Example Report Structure**:
```
Subject: [SECURITY] SQL Injection in Admin Panel

Impact: SQL Injection leading to authentication bypass

Affected Versions: v10.0.0 and earlier

Steps to Reproduce:
1. Navigate to /admin/login
2. Enter the following in the username field: ' OR '1'='1
3. Click login
4. Observe successful authentication without valid credentials

Root Cause: User input not sanitized before SQL query construction in AdminController.cs line 45

Proof of Concept:
[Code snippet or screenshot]
```

## Security Advisories

Published security advisories can be found in the [GitHub Security Advisories](https://github.com/TechnitiumSoftware/DnsServer/security/advisories) section.

---

Thank you for helping keep Technitium DNS Server and our users safe!
