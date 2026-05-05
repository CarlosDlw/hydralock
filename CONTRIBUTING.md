# Contributing

Thanks for contributing to HydraLock.

## Development Setup

1. Install Rust stable toolchain.
2. Clone the repository.
3. Run checks locally:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cd impl/python && python -m unittest -v
```

## Pull Request Rules

1. Keep changes focused and scoped to one objective.
2. Include tests for behavior changes.
3. Update specs/docs when changing wire format, cryptographic behavior, or CLI semantics.
4. Do not merge if CI fails.

## Commit Guidance

Use clear commit messages:

- `feat: ...`
- `fix: ...`
- `docs: ...`
- `test: ...`
- `chore: ...`

## Cryptographic Change Policy

Any PR touching key derivation, AAD, section layouts, wrapper formats, metadata encoding, or rewrap behavior must include:

1. regression tests;
2. vector impact note;
3. spec alignment update.

## Security Reports

Do not open public issues for vulnerabilities.
Use the process in SECURITY.md.