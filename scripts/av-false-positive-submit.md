# AV False Positive Submission Guide

When a new rsh build is flagged by antivirus engines on VirusTotal, submit
false positive reports to get the detection removed.

## Submission Links

| Vendor | URL | Method |
|--------|-----|--------|
| Microsoft (Defender) | https://www.microsoft.com/en-us/wdsi/filesubmission | Upload .exe, select "Should not be detected" |
| ESET (NOD32) | samples@eset.com | Email with .exe attached (or via ESET product: Tools > Quarantine > Submit) |
| Kaspersky | https://opentip.kaspersky.com/ | Upload for analysis, report false positive |
| Bitdefender | https://www.bitdefender.com/consumer/support/answer/29358/ | Upload sample |
| Avast/AVG | https://www.avast.com/false-positive-file-form.php | Upload .exe |
| Malwarebytes | https://forums.malwarebytes.com/forum/42-file-detections/ | Forum post with sample |
| Sophos | https://support.sophos.com/support/s/filesubmission | Upload + describe |
| Trend Micro | https://www.trendmicro.com/en_us/about/legal/detection-reevaluation.html | Upload for reevaluation |

## Submission Template

```
Subject: False Positive - Remote Shell (rsh) v<VERSION>

This is a legitimate remote administration tool written in Rust.

Product: Remote Shell (rsh)
Company: Pinesoft
Version: <VERSION>
Language: Rust (cross-compiled with cargo for Windows)
Purpose: Secure remote server management (SSH-like, ed25519 auth)
SHA256: <HASH>

The file is a cross-compiled Rust binary for Windows which includes:
- Ed25519 public key authentication
- TLS encrypted communication
- Windows service registration
- System tray integration

Rust binaries may be false-positived by heuristic engines due to
uncommon PE structure or low prevalence.

VirusTotal: https://www.virustotal.com/gui/file/<HASH>
```

## Workflow

1. Build new version
2. Run `scripts/vt-check.sh deploy/rsh.exe`
3. If flagged: submit to each flagging vendor using links above
4. Wait 1-7 days for vendor review
5. Re-check on VirusTotal
6. Document results in commit message
