# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Ephemera is a Lambda Function URL proxy for internal backend services. It provides wildcard CloudFront distribution proxying to internal backends with Google OIDC authentication, time-based access control (expiring host records), and email-based user authorization.

## Build & Development Commands

All commands use [Task](https://taskfile.dev/) (Taskfile.yaml):

- `task build` — Build static Linux x86_64 binary (`bootstrap`) with `-tags lambda.norpc`
- `task run` — Run locally with auto-reload via reflex (port 5003)
- `task deploy` — Build and deploy to AWS Lambda via lambroll
- `task build-image` — Build Docker image
- `task push-image` — Build and push Docker image to ECR
- `task logs` — Tail Lambda function logs
- `task clean` — Remove bootstrap binary

There are no tests in the codebase.

## Environment Configuration

Configuration is via environment variables (see `envrc.sample`):
- `EPHEMERA_S3_BUCKET_NAME` — S3 bucket holding `hosts.json` and `authorities.json`
- `EPHEMERA_HOST_SUFFIX` — Base domain for wildcard subdomains
- `EPHEMERA_AUTH_SUBDOMAIN` — Subdomain name for the auth service
- `EPHEMERA_SESSION_KEY` — Cookie encryption key
- `EPHEMERA_CLIENT_ID` / `EPHEMERA_CLIENT_SECRET` — Google OAuth credentials

## Architecture

**Language:** Go 1.23 · **Runtime:** AWS Lambda custom runtime (provided.al2023) via [ridge](https://github.com/fujiwara/ridge)

### Request Flow

```
Client → GeneralHandler (main.go)
  ├─ Auth subdomain → auth.Server handles OIDC sign-in/callback/verify
  └─ App subdomain → check hosts.json (expiry + auth) → reverse proxy to backend target
```

### Key Components

- **main.go** — Entry point, `GeneralHandler` routes requests. Loads `hosts.json` (subdomain→target routing with expiry) and `authorities.json` (email→allowed subdomains) from S3 on each request.
- **auth/** — Authentication package:
  - `server.go` — HTTP handlers for `/auth/sign_in`, `/auth/start`, `/auth/callback`, `/auth/verify`, and default page. Manages three session cookies (`ephemera_auth_session`, `ephemera_session`, `ephemera_gate`).
  - `authenticator.go` — OIDC token verification, uses Google implicit flow (`response_type=id_token`).
  - `google_auth.go` — Google OIDC provider wrapper.
  - `session.go` — `ExtractSession()` retrieves and validates login session from cookies.

### S3 Configuration Files

Two JSON files are loaded from S3 at runtime:
- **hosts.json** — Array of `HostRecord` (Subdomain, Target, ExpireAt, NeedAuth)
- **authorities.json** — Map of email → allowed subdomain list (`"*"` = all)

### Session Model

- `ephemera_auth_session` — Temporary (5 min), used during OAuth flow
- `ephemera_session` — Persistent login (30 days), cross-subdomain via host suffix domain
- `ephemera_gate` — Stores post-login redirect URL
