# Security Policy

## Reporting

Do not include proxy usernames, passwords, subscription URLs, or full diagnostic reports in public issues.

For vulnerabilities in this application, open a private GitHub security advisory for this repository.

## Design Boundaries

- The application accepts an unauthenticated HTTP or mixed local proxy endpoint.
- Proxy host, port, and timeout values are validated before use.
- API responses are size-limited and console output is stripped of control characters.
- The release executable is statically compiled and does not execute downloaded code.
- Network access is required because IP quality checks depend on external services.
- Release binaries are currently unsigned. Verify the published SHA-256 checksum or build from source.
