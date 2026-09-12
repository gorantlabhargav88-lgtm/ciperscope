# Phase 9: SPF, DKIM, and DMARC Independent Verification

## Overview
Phase 9 introduces a robust, independent verification engine for email authentication (SPF, DKIM, DMARC) designed specifically for forensic and security operations contexts.

Unlike standard email clients or MTAs which implicitly trust the headers attached to an email (e.g., `Authentication-Results`), CiperScope **re-evaluates all authentication claims independently** using controlled DNS resolution. 

This ensures that attackers cannot easily forge passing results by injecting spoofed headers into the message body or manipulating upstream MTA logs.

## Architecture

### 1. The `DnsResolver` Abstraction
All verification relies on `DnsResolver`. This component enforces:
- **Max Lookups (e.g., 50)**: Prevents DNS recursion exhaustion attacks (often seen in maliciously crafted SPF records with infinite loops).
- **Strict Timeouts (e.g., 2000ms)**: Ensures verifier does not hang on unresponsive DNS servers.
- **In-Memory Caching**: Avoids redundant lookups during a single evaluation lifecycle.

### 2. SPF Verification (`SpfVerifier`)
- Retrieves the earliest external hop IP from the `RelayHop` chain.
- Looks up the `Return-Path` domain.
- Evaluates mechanisms (`ip4`, `ip6`, `a`, `mx`, `include`, `all`) with strict depth limits.

### 3. DKIM Verification (`DkimVerifier`)
- Parses all `DKIM-Signature` headers attached to the message.
- Retrieves public keys via `selector._domainkey.domain` TXT records.
- Performs validations, enforcing that HTTP/HTTPS fetching of DKIM public keys or extensions is **strictly prohibited**.

### 4. DMARC Verification (`DmarcVerifier`)
- Extracts the Organizational Domain securely using the Public Suffix List (`psl`).
- Checks SPF alignment (`aspf`) and DKIM alignment (`adkim`).
- Ensures at least one protocol aligns and passes to yield a DMARC `PASS`.

## Forensic Consistency Check
The system automatically compares the independent verification results with the claimed `Authentication-Results` header. If a mismatch is detected (e.g., header claims `PASS` but independent verification yields `FAIL`), the UI flags the inconsistency for the security analyst, indicating potential header spoofing or upstream MTA misconfiguration.
