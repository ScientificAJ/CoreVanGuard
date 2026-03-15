# Code Signing Preparation

CoreVanguard will need three distinct signing lanes:

## Windows development signing

- Enable local kernel test-signing with `bcdedit /set testsigning on`.
- Store a development PFX in `WINDOWS_TEST_CERT_BASE64`.
- Store its password in `WINDOWS_TEST_CERT_PASSWORD`.
- Use these only for CI development builds and local driver loading.

## Windows production signing

- `WINDOWS_EV_CERT_BASE64`
- `WINDOWS_EV_CERT_PASSWORD`
- `WINDOWS_EV_CERT_SUBJECT`

These secret names reserve the future EV code-signing certificate chain required for production trust and SmartScreen reputation work.

## macOS production signing

- `APPLE_SIGNING_CERT_BASE64`
- `APPLE_SIGNING_CERT_PASSWORD`
- `APPLE_KEYCHAIN_PASSWORD`
- `APPLE_TEAM_ID`
- `APPLE_DEVELOPER_ID_APPLICATION`
- `APPLE_DEVELOPER_ID_INSTALLER`

The macOS system extension path will also require the Endpoint Security entitlement and the correct notarization pipeline before distribution.

## Operational rules

- Never commit certificates, provisioning files, or entitlements with private material.
- Keep test-signing and production-signing secrets isolated.
- Gate production signing behind protected branches or environment approvals.
- Treat certificate rotation as a release-blocking event, not a best-effort chore.
