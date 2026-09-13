# Phase 10: URL & Attachment Threat Analysis

Phase 10 introduces the Threat Analysis subsystem for extracting and safely analyzing URLs and attachments from ingested emails.

## Overview

- **URL Extraction**: URLs are extracted from text and HTML parts using regex and `cheerio`.
- **URL Normalization**: Observed URLs are retained while generating normalized URLs safely. Obfuscation indicators (percent encoding, IP literals) are recorded.
- **Attachment Analysis**: Stream-based hashing (SHA-256) and magic-byte signature checking.
- **Archive Safety**: ZIP metadata is read using `yauzl` with strict limitations on size, entry count, and recursion to prevent zip bombs.

## Disclaimer

Phase 10 is PASSIVE ANALYSIS.

It does not prove:
- attacker identity;
- attacker location;
- malicious intent;
- successful compromise;
- URL reputation;
- malware execution;
- attribution.
