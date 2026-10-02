# 🔐 Security

## Reporting

Do not publish credentials, tokens, private datasets, personal data or exploitable details in a public issue.

For security-sensitive reports, provide the minimum information required to reproduce and understand the issue.

## Boundaries

This repository is designed around public-source research and authorized security work.

Do not use project automation to bypass authentication, defeat access controls or collect non-public information.

## Secrets

Never commit:

- API keys;
- session cookies;
- webhook secrets;
- private keys;
- passwords;
- `.env` files containing credentials.

Prefer GitHub Actions Secrets or environment variables for CI configuration.

> **⚡ xLFr4n — evidence first, secrets never.**