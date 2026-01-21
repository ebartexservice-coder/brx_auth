# Security Policy

## 🔒 Security Best Practices

This repository follows strict security practices to protect sensitive information.

### ⚠️ NEVER COMMIT

The following files and information should **NEVER** be committed to the repository:

- **Environment files**: `.env`, `.env.local`, `.env.production`
- **Private keys**: `*.pem`, `*.key`, `*.rsa`, `*.p12`
- **Certificates**: `*.crt`, `*.cert`
- **Database credentials**: Connection strings with real passwords
- **API keys**: AWS keys, Redis passwords, etc.
- **JWT private keys**: RSA private keys for token signing

### ✅ Safe to Commit

- `env.example`: Template file with placeholder values
- `requirements.txt`: Python dependencies
- Source code (without hardcoded secrets)
- Documentation files

### 🔑 Key Management

**Development:**
- Use `.env` file (gitignored) for local development
- Generate test keys: `openssl genrsa -out private_key.pem 2048`

**Production:**
- Load keys from AWS SSM Parameter Store
- Use environment variables injected by deployment system
- Never store keys in code or configuration files

### 🛡️ Security Features

- **Password Hashing**: Argon2id (industry standard)
- **JWT Signing**: RS256 (asymmetric keys)
- **Token Blacklisting**: Redis-based revocation
- **Rate Limiting**: Brute force protection
- **SQL Injection**: ORM-based queries only

### 📝 Reporting Security Issues

If you discover a security vulnerability, please:
1. **DO NOT** open a public issue
2. Contact the security team directly
3. Provide detailed information about the vulnerability

### 🔍 Security Checklist

Before pushing code:
- [ ] No `.env` files in repository
- [ ] No private keys or certificates
- [ ] No hardcoded passwords or secrets
- [ ] All sensitive data in environment variables
- [ ] `.gitignore` properly configured
- [ ] `env.example` updated with placeholders only
