# Security Policy

## Reporting a Vulnerability

Please report security issues privately by email:

```text
security@valicode.sbs
```

Include:

- Affected command or workflow
- Steps to reproduce
- Impact
- Any relevant logs or sample files, with secrets removed

Do not open public GitHub issues for vulnerabilities.

## Data Handling

The CLI stores the API key locally in `~/.valicode/config.toml`.

Before scanning a workspace, you can inspect the file list without sending data:

```bash
valicode scan . --dry-run
```

The CLI excludes common dependency folders, build outputs, caches, virtual environments, binary files, archives, media files, VCS metadata, and real environment files by default.
