Deployment Guide
================

This document outlines a recommended path to deploy the LogGuard FastAPI web UI securely.

1) Build a Docker image

```bash
docker build -t logguard:latest .
```

2) Run locally with environment variables (never put secrets in files):

```bash
docker run -e SMTP_PASSWORD="$SMTP_PASSWORD" -e CONFIG_PATH=/app/config/config.yaml -p 8000:8000 logguard:latest
```

3) Recommended hosts

- Render (easy GitHub integration, managed, free/paid tiers): push image or enable Docker deploy.
- Fly.io (good for low-latency global apps): `fly deploy`.
- DigitalOcean App Platform: connect repo and set secrets via UI.
- AWS Elastic Beanstalk / ECS / Fargate: use task definitions with secrets from Secrets Manager.
- Azure App Service / Web Apps: use deployment center + App Settings for secrets.

Use a secret manager (Render/DO/AWS/Azure) to provide `SMTP_PASSWORD`, DB credentials, and other secrets.

Reverse proxy and TLS

- Put Nginx or built-in platform load balancer in front of Uvicorn/ASGI.
- Terminate TLS at the load balancer (Let's Encrypt via Certbot or platform-managed certs).

CI/CD

- GitHub Actions `ci.yml` runs tests and scans for secrets. Configure a protected branch and require passing checks before merge.
