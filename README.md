# AppAudix Security Scan Action

Scan your mobile applications (Android APK/AAB, iOS IPA) for security vulnerabilities and compliance issues directly in your GitHub Actions workflow.

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-AppAudix%20Scan-blue?logo=github)](https://github.com/marketplace/actions/appaudix-security-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Multi-Framework Compliance**: PCI-DSS 4.0, OWASP MASVS, HIPAA, GDPR, SOC 2, NIST
- **SARIF Integration**: Upload results to GitHub Code Scanning for PR annotations
- **Configurable Thresholds**: Fail builds based on severity levels
- **Fast Scanning**: Typical scans complete in 5-15 minutes
- **Full Reports**: PDF, HTML, JSON, and SARIF formats available

## Quick Start

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Build Android App
        run: ./gradlew assembleRelease

      - name: AppAudix Security Scan
        uses: appaudix/scan-action@v1
        with:
          api-key: ${{ secrets.APPAUDIX_API_KEY }}
          file: app/build/outputs/apk/release/app-release.apk
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `api-key` | AppAudix API key | Yes | - |
| `file` | Path to APK, AAB, or IPA file | Yes | - |
| `frameworks` | Compliance frameworks (comma-separated) | No | `pci_dss` |
| `fail-on` | Fail if issues at this severity or higher | No | `critical` |
| `upload-sarif` | Upload SARIF to GitHub Code Scanning | No | `true` |
| `wait-for-completion` | Wait for scan to complete | No | `true` |
| `timeout-minutes` | Max wait time for scan | No | `30` |
| `api-url` | API base URL (for self-hosted) | No | `https://api.appaudix.com` |

### Frameworks

| Value | Description |
|-------|-------------|
| `pci_dss` | PCI-DSS 4.0.1 - Payment Card Industry |
| `owasp_masvs` | OWASP Mobile Application Security |
| `hipaa` | HIPAA - Healthcare Data Protection |
| `gdpr` | GDPR - Privacy Compliance |
| `soc2` | SOC 2 Type II - Security Controls |
| `nist` | NIST 800-53 - Federal Security |

### Fail-On Levels

| Value | Description |
|-------|-------------|
| `critical` | Fail only on critical issues (default) |
| `high` | Fail on high or critical issues |
| `medium` | Fail on medium, high, or critical issues |
| `low` | Fail on any issues |
| `none` | Never fail (report only) |

## Outputs

| Output | Description |
|--------|-------------|
| `scan-id` | Unique scan identifier |
| `status` | Final status (completed, error, cancelled) |
| `compliance-score` | Overall score (0-100) |
| `risk-level` | CRITICAL, HIGH, MEDIUM, LOW, or MINIMAL |
| `critical-count` | Number of critical issues |
| `high-count` | Number of high issues |
| `medium-count` | Number of medium issues |
| `low-count` | Number of low issues |
| `report-url` | URL to full report |
| `sarif-file` | Path to downloaded SARIF file |

## Examples

### Android APK with Multiple Frameworks

```yaml
- name: Security Scan
  uses: appaudix/scan-action@v1
  with:
    api-key: ${{ secrets.APPAUDIX_API_KEY }}
    file: app/build/outputs/apk/release/app-release.apk
    frameworks: pci_dss,owasp_masvs,gdpr
    fail-on: high
```

### Android App Bundle (AAB)

```yaml
- name: Security Scan
  uses: appaudix/scan-action@v1
  with:
    api-key: ${{ secrets.APPAUDIX_API_KEY }}
    file: app/build/outputs/bundle/release/app-release.aab
    frameworks: pci_dss
```

### iOS IPA

```yaml
jobs:
  security-scan:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build iOS App
        run: |
          xcodebuild -workspace MyApp.xcworkspace \
            -scheme MyApp \
            -sdk iphoneos \
            -configuration Release \
            archive -archivePath build/MyApp.xcarchive

          xcodebuild -exportArchive \
            -archivePath build/MyApp.xcarchive \
            -exportPath build/ \
            -exportOptionsPlist ExportOptions.plist

      - name: Security Scan
        uses: appaudix/scan-action@v1
        with:
          api-key: ${{ secrets.APPAUDIX_API_KEY }}
          file: build/MyApp.ipa
          frameworks: pci_dss,hipaa
```

### Flutter (Android + iOS)

```yaml
jobs:
  build-and-scan:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            platform: android
            file: build/app/outputs/flutter-apk/app-release.apk
          - os: macos-latest
            platform: ios
            file: build/ios/ipa/MyApp.ipa

    runs-on: ${{ matrix.os }}
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2

      - name: Build ${{ matrix.platform }}
        run: |
          flutter pub get
          flutter build ${{ matrix.platform == 'android' && 'apk --release' || 'ipa --release' }}

      - name: Security Scan
        uses: appaudix/scan-action@v1
        with:
          api-key: ${{ secrets.APPAUDIX_API_KEY }}
          file: ${{ matrix.file }}
          frameworks: pci_dss,owasp_masvs
```

### React Native

```yaml
- name: Build Android
  run: |
    cd android
    ./gradlew assembleRelease

- name: Security Scan
  uses: appaudix/scan-action@v1
  with:
    api-key: ${{ secrets.APPAUDIX_API_KEY }}
    file: android/app/build/outputs/apk/release/app-release.apk
```

### Conditional Deployment

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    outputs:
      passed: ${{ steps.scan.outputs.compliance-score >= 80 }}
      score: ${{ steps.scan.outputs.compliance-score }}

    steps:
      - uses: actions/checkout@v4
      - run: ./gradlew assembleRelease

      - name: Security Scan
        id: scan
        uses: appaudix/scan-action@v1
        with:
          api-key: ${{ secrets.APPAUDIX_API_KEY }}
          file: app/build/outputs/apk/release/app-release.apk
          fail-on: none  # Don't fail, just report

      - name: Check Score
        run: |
          echo "Compliance Score: ${{ steps.scan.outputs.compliance-score }}%"
          echo "Risk Level: ${{ steps.scan.outputs.risk-level }}"

  deploy:
    needs: security-scan
    if: needs.security-scan.outputs.passed == 'true'
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying app with score ${{ needs.security-scan.outputs.score }}%"
```

### Report Only (No Fail)

```yaml
- name: Security Scan
  uses: appaudix/scan-action@v1
  with:
    api-key: ${{ secrets.APPAUDIX_API_KEY }}
    file: app-release.apk
    fail-on: none
    upload-sarif: true
```

### Async Scan (Don't Wait)

```yaml
- name: Start Security Scan
  id: scan
  uses: appaudix/scan-action@v1
  with:
    api-key: ${{ secrets.APPAUDIX_API_KEY }}
    file: app-release.apk
    wait-for-completion: false

- name: Continue with other steps
  run: echo "Scan started with ID ${{ steps.scan.outputs.scan-id }}"
```

## GitHub Code Scanning Integration

When `upload-sarif: true` (default), scan results appear in:
- **Security tab** → Code scanning alerts
- **Pull request** → Security annotations on changed files

### Required Permissions

```yaml
permissions:
  security-events: write  # Upload SARIF
  contents: read          # Checkout code
```

### SARIF in Pull Requests

Security issues will appear as annotations directly on the PR:

```
⚠️ AppAudix: Hardcoded API key detected
   Severity: Critical
   Framework: PCI-DSS 3.4.1
   File: com/example/Config.java:42
```

## Getting an API Key

1. Sign up at [appaudix.com](https://appaudix.com)
2. Go to Settings → API Keys
3. Generate a new API key
4. Add it as a repository secret: `APPAUDIX_API_KEY`

## Support

- **Documentation**: [appaudix.com/apidocs](https://appaudix.com/apidocs)
- **Issues**: [github.com/AppAudix/scan-action/issues](https://github.com/AppAudix/scan-action/issues)
- **Email**: support@appaudix.com

## License

MIT License - see [LICENSE](LICENSE) for details.
