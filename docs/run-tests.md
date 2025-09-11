# Running Unit Tests

Use the provided cross-platform scripts to execute the unit test suite with race detector and coverage.

- Windows (PowerShell):
  - `./scripts/test.ps1` — run tests
  - `./scripts/test.ps1 -Html` — additionally generate `coverage.html`

- Linux/macOS:
  - `bash ./scripts/test.sh`

Notes
- The scripts set `DISABLE_HTTPS_REDIRECT=true` to avoid HTTPS redirects interfering with handler tests.
- Coverage summary is printed; full profile saved in `coverage.out`.

