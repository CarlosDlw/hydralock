# Releasing HydraLock

This repository is configured for automatic releases from tags.

## Zero-command release flow

1. Open GitHub repository page.
2. Go to Releases.
3. Click Draft a new release.
4. Set a new tag in the format `vX.Y.Z` (for example, `v1.0.0`).
5. Publish release.

After tag creation, GitHub Actions will automatically:

1. build release binaries;
2. package artifacts for Linux and Windows;
3. generate SHA-256 checksum files;
4. create/update GitHub Release notes automatically;
5. upload all artifacts to the release page.

## Produced artifacts

- `hydralock-<tag>-x86_64-unknown-linux-gnu.tar.gz`
- `hydralock-<tag>-x86_64-unknown-linux-gnu.tar.gz.sha256`
- `hydralock-<tag>-x86_64-pc-windows-msvc.zip`
- `hydralock-<tag>-x86_64-pc-windows-msvc.zip.sha256`

## Notes quality

Release notes are generated from merged pull requests and grouped by labels via `.github/release.yml`.