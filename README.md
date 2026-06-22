# Valicode CLI

Valicode audits code changes for security, reliability, and production readiness before they ship.

This repository contains the public CLI source distributed on PyPI and npm as `valicode`.
The hosted API, dashboard, billing, admin tools, and infrastructure are not part of this repository.

## Install

Python / pip:

```bash
python -m pip install valicode
```

Node / npm:

```bash
npm install -g valicode
```

One-off npm usage:

```bash
npx valicode scan . --output summary
```

Requires Python 3.10 or newer. The npm package is a lightweight wrapper that creates an isolated Python environment and runs the same Valicode CLI engine published on PyPI.

## Authenticate

Create an API key in the Valicode dashboard:

```text
https://valicode.sbs/dashboard/api-keys
```

Then save it locally:

```bash
valicode login
```

The key is stored in:

```text
~/.valicode/config.toml
```

## Run

Preview what would be sent:

```bash
valicode scan . --dry-run
```

Analyze a workspace:

```bash
valicode scan . --output summary
```

Analyze staged changes:

```bash
git add .
valicode analyze --staged
```

## API Endpoint

The CLI uses the production API by default:

```text
https://api.valicode.sbs/v1
```

Override it when needed:

```bash
valicode config set api_base https://api.valicode.sbs/v1
```

or:

```bash
export VALICODE_API_BASE=https://api.valicode.sbs/v1
```

## What Gets Sent

`valicode scan` converts eligible source files into a diff-like payload and sends it to the Valicode API for analysis. By default it ignores dependency folders, build output, VCS metadata, caches, virtual environments, binaries, images, archives, and real environment files.

Use this before sending data:

```bash
valicode scan . --dry-run
```

For a smaller request, analyze only staged changes or a specific diff.

## Useful Commands

```bash
valicode --version
valicode doctor --check-api
valicode scan . --dry-run
valicode scan . --output summary
valicode analyze --staged --no-context
```

## Links

- Website: https://valicode.sbs
- Docs: https://valicode.sbs/docs
- PyPI: https://pypi.org/project/valicode/
- npm: https://www.npmjs.com/package/valicode
- Security reports: see [SECURITY.md](SECURITY.md)
