---
title: 'Honeypot Observations on PHP Vulnerabilities CVE-2026-109618 and CVE-2026-109619 (php2shell)'
header: 'Honeypot Observations on PHP Vulnerabilities CVE-2026-109618 and CVE-2026-109619 (php2shell)'
og_description: 'What our honeypots saw around the disclosure of the critical PHP vulnerabilities CVE-2026-109618 and CVE-2026-109619 (php2shell).'
og_image: "/assets/images/php2shell.png"
tags: ['ThreatIntel', 'Honeypots']
---

On 21 October 2026, the PHP project disclosed two critical vulnerabilities in PHP core, dubbed "php2shell". We went through a week of our honeypot data to see who came knocking. The short answer: many checkers, some fuzzing, and a single source sending exploit-like payloads, which arrived 45 minutes after the advisories. <!--more-->

## Key Takeaways

- **Before disclosure, only probes.** In the eight hours before the advisories, our sensors saw parser fuzzing, a self-labelled php2shell audit and tests for the upload-progress field. None of these requests carried an exploit-like payload.
- **One exploitation source, after disclosure.** A single address sent crafted serialized PHP payloads between 14:18 and 15:51 UTC on 21 October.
- **Checkers outnumber attackers.** By midnight, at least ten different php2shell-themed User-Agents had probed our sensors. Most sent nothing more than a GET request.
- **Unusual is not the same as php2shell.** Chunked and length-less multipart requests looked suspicious, but almost all of them came from generic scanners that had sent them long before disclosure.

## Background

CVE-2026-109618 ("RCE via OOM corruption") and CVE-2026-109619 ("RCE via stale global state") are both rated critical (CVSS v4.0 9.2) and allow unauthenticated remote code execution. Both sit in the request handling of PHP core, including multipart parsing and session upload progress. For details, see the [PHP announcement](https://www.php.net/archive/2026.php) and the advisories [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

The advisories went live on 21 October at 13:34 UTC. Amazon [reported](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/) a first exploitation attempt against its honeypots on 17 October, and public proofs of concept from about 02:00 UTC on 21 October.

## Timeline

All times are UTC. Before 21 October, we saw nothing php2shell-specific.

| Time (21 Oct) | Source | Observation |
|---|---|---|
| 05:25 | 64.176.35[.]212 | Parser-limit fuzzing begins |
| 07:41 | 20.243.201[.]81 | First "php2shell" string in our data, from a self-labelled audit |
| 08:43 | 185.182.195[.]133 | Upload-progress detection test |
| 10:10 | 185.4.112[.]42 | Upload-progress probe |
| **13:34** | – | **Advisories published** |
| 14:18 | 45.198.224[.]169 | Exploit-like serialized payloads, until 15:51 |
| 15:34 | various | Wave of self-labelled php2shell checkers begins |
| 17:56 | 64.176.35[.]212 | Second fuzzing phase, until 23:50 |
| 23:24 | 45.198.224[.]110 | Chunked multipart checker with deeply nested field names |

## What We Observed

### Before disclosure: fuzzing and tests

Five sources showed up in the eight hours before the advisories. None of them sent an exploit-like payload.

| Source | What it sent | Assessment |
|---|---|---|
| 64.176.35[.]212 (Vultr, JP) | Tens of thousands of requests, many of them stressing PHP's request parser | Unclear |
| 20.243.201[.]81 (Azure, JP) | Requests for phpinfo-style paths with a "php2shell" scan ID | Checker |
| 185.182.195[.]133 | The upload-progress field, posted to two "trap" scripts | Detection test |
| 185.4.112[.]42 | The upload-progress field in tiny multipart POSTs | Checker |
| 85.11.167[.]243 | 41 bare requests for `/index.php` | Unclear |

#### Parser fuzzing

The busiest source, 64.176.35[.]212, spent the morning pushing PHP's request parser to its limits, and came back for a second round in the evening. Its traffic fits the memory-pressure precondition of CVE-2026-109618. It never named itself and never sent an upload-progress field, so we cannot tell whether a researcher or an attacker was behind it.

| Technique | Range observed (both rounds) |
|---|---|
| urlencoded bodies | 50–450 KB, up to 10,000 fields |
| Nested array brackets in the query string | 32–39 levels (`?a[b][b][b]…`) |
| Multipart bodies | up to 329 KB, one with 100,000 raw NUL bytes |
| `Content-Length` header | 2<sup>64</sup>−1 and 2<sup>63</sup> |

#### A self-labelled audit

The first "php2shell" string in our data arrived at 07:41 UTC, in a request header:

```http
User-Agent: Company-PHP-Audit/0.1.0
X-Company-Scan-Id: php2shell-full-20261021_163651_JST-…
X-PHP-Audit-Stage: …
```

The timestamp in the scan ID converts to 07:36:51 UTC, a few minutes before the first request reached us. A second run followed at 19:22 UTC with version 0.5.0.

#### Tests for the upload-progress field

Two sources sent the `PHP_SESSION_UPLOAD_PROGRESS` field in tiny POST bodies of 29 to 296 bytes. One posted it to scripts named `/trap-encoded.php` and `/trap-literal.php`, with the User-Agent `trap-test-rev2`. This looks like someone testing their detection rules against an encoded and a literal field name. The other used plain curl. Before disclosure, the field reached our sensors only in tests like these.

#### Unclear: minimal GET requests

85.11.167[.]243, otherwise busy with IoT and NVR exploits, requested the PHP index page 41 times within ten minutes. The requests carried nothing but a Connection header and the literal User-Agent `None`. The exploitation source described below used the same style later that day. The style is common, though: another address had been sending identical requests daily since 15 October.

### After disclosure: one exploitation source

45.198.224[.]169 had been scanning our sensors since 16 October, but only generically, including probes against DVR ports. About 45 minutes after the advisories, it switched to crafted POST requests against three PHP entry points. Every request carried a single form parameter named `cook`:

| | Probes | Payloads |
|---|---|---|
| Requests | 72 | 8 |
| `Content-Length` | 13 | 28,296 |
| Value of `cook` | short serialized PHP scalar | serialized PHP array (`a:41:{…`) with the class name `CachedData` and long runs of raw NUL bytes |

All requests share the same minimal client fingerprint. The paths were `/index.php`, `/` and `/remote_app.php` (Host header omitted):

```http
POST /index.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 28296
Connection: …
User-Agent: None

cook=a:41:{…
```

We saw no multipart body, no upload-progress field and no session cookie from this source. Our data does not show whether these payloads target either of the two CVEs.

### After disclosure: a wave of checkers

From 15:34 UTC, scanners that named themselves after php2shell arrived in quick succession. Most sent a single GET request and moved on.

| Time | Source | User-Agent | Note |
|---|---|---|---|
| 15:34 | 91.90.123[.]25 | `php2shell-verify/1.0` | Mullvad VPN exit |
| 17:32 | 143.198.209[.]212 | `php2shell/2.0 (patch-state check)` | small multipart POST |
| 18:12 | 94.154.43[.]222 | `php2shell-scan/1.0` | also unrelated PHP exploits |
| 18:30 | 185.218.86[.]14 | `Mozilla/5.0 (X11; Linux x86_64) php2shell-detect/1.0` | |
| 19:17 | 91.90.123[.]5 | `php2shell-scan/2.0`, `php2shell-scan/3.1 (authorized-security-assessment)` | same VPN range |
| 20:05 | 36.70.239[.]195 | `Mozilla/5.0 php2shell-checker/1.0`, `php2shell-check/1.0` | |
| 22:00 | 217.60.242[.]58 | `shellflow-php2shell/1.0` | |
| 23:24 | 45.198.224[.]110 | `php2shell-behavioral-check/2.0`, `php-cve-version-check/1.0` | see below |

#### The odd one out

The last checker of the day, 45.198.224[.]110, did more than ask for phpinfo pages. It sent ten POST requests built to stress the multipart parser:

```http
POST / HTTP/1.1
Transfer-Encoding: chunked
Content-Type: multipart/form-data; boundary=----p2sBoundary9f2b7a
```

There was no Content-Length header. Each 607-byte body held one form field whose name was nested 200 levels deep. The ten requests used two fixed bodies, five each; their hashes are listed below. The address sits in the same /24 as the exploitation source, but nothing else connects them: they used different User-Agents, techniques and times, and the /24 hosts 70 active sources.

### Unusual is not the same as php2shell

Hunting for odd multipart requests alone mostly finds noise. Our week of data held 347 chunked multipart requests and 1,164 multipart requests without a Content-Length header. Between 97 and 99 % of them arrived before disclosure, from generic web scanners without any php2shell-specific marker.

### Comparison with Amazon's report

Only one of the six IP addresses from Amazon's report reached our sensors: 31.223.184[.]166 made six connections to a Dionaea honeypot on 19 October, without any HTTP content. The 17 October source did not appear at all. Different sensor networks see different traffic, so this neither confirms nor contradicts earlier exploitation.

## Hunting Recommendations

The traffic that reached our honeypots suggests a few signals for web server, WAF and proxy logs. Amazon recommends looking back to at least 17 October; in our data, the first related requests appeared on 21 October.

| Signal | What it meant in our data | How to use it |
|---|---|---|
| urlencoded POST with raw NUL bytes and serialized PHP data (`a:<n>:{`, `O:<n>:"`) in a parameter | The only exploit-like payloads | Strongest signal in our data |
| `PHP_SESSION_UPLOAD_PROGRESS` in a POST body | Tests and probes, all before disclosure | Rare in legitimate traffic: review every hit |
| User-Agent containing `php2shell` or `php-cve-version-check` | Checkers, never an exploit payload | Indicates scanning, not exploitation |
| Literal User-Agent `None` with only a Connection header | The exploitation source, but also unrelated scripts | Supporting signal only |
| Chunked multipart, multipart without Content-Length, deeply nested field names, very large form bodies | Almost always generic scanners or fuzzing | Supporting signal only |

When rating a hit, three lessons from our data help:

- **A checker hit means a host is being scanned, not compromised.** Self-labelled checkers made up most of the php2shell traffic we saw.
- **Combine weak signals.** Odd multipart requests alone are mostly noise. Together with an upload-progress field or a php2shell User-Agent, they deserve a closer look.
- **Treat IP matches as leads, not proof.** Several sources above are VPN exits or cloud hosts shared by many users.

An exploit-like request shows an attempt, not its outcome. Our honeypots cannot tell whether a payload would have worked, so check the targeted host for the same time window.

## Limitations

- **No success signal:** our honeypots answer generically. They show what was sent, not whether it would have worked against a real PHP installation.
- **Incomplete bodies:** some sensors truncate request bodies, drop multipart part headers or store headers only. A missing marker does not prove that it was not sent.

## Indicators

The roles reflect what our sensors captured. Several addresses are VPN exits or cloud hosts and may be shared.

| IP address | Role | Relevant activity on 21 Oct (UTC) |
|---|---|---|
| `45.198.224[.]169` | exploitation attempts | 14:18–15:51 |
| `64.176.35[.]212` | unclear: parser fuzzing | 05:25–23:58 |
| `85.11.167[.]243` | unclear: minimal GET requests | 08:36–08:46 |
| `20.243.201[.]81` | checker | 07:41–19:22 |
| `185.182.195[.]133` | detection test | 08:43 |
| `185.4.112[.]42` | checker | 10:10–10:11 |
| `91.90.123[.]25` | checker | 15:34–20:58 |
| `143.198.209[.]212` | checker | 17:32 |
| `94.154.43[.]222` | checker | 18:12–18:17 |
| `185.218.86[.]14` | checker | 18:30 |
| `91.90.123[.]5` | checker | 19:17–19:50 |
| `36.70.239[.]195` | checker | 20:05–22:19 |
| `217.60.242[.]58` | checker | 22:00–22:46 |
| `45.198.224[.]110` | checker | 23:24–23:56 |

| Request marker | Source |
|---|---|
| Parameter `cook=` with serialized `CachedData` payload, User-Agent `None` | 45.198.224[.]169 |
| Boundary `----p2sBoundary9f2b7a`, chunked, no `Content-Length` | 45.198.224[.]110 |
| Boundary `----php2shell` followed by 12 hex characters | 143.198.209[.]212 |
| Boundary `----artexboundary78` | 64.176.35[.]212 |
| Header `X-Company-Scan-Id: php2shell-full-*` | 20.243.201[.]81 |

## Run Your Own Honeypots

The honeypots that captured this activity, such as Tanner, H0neytr4p and Dionaea, are all part of [T-Pot](https://github.com/telekom-security/tpotce), our open-source multi-honeypot platform. T-Pot bundles more than 20 honeypots with the Elastic Stack for analysis and visualization, and installs on a single host. If you want to see for yourself what hits the internet after the next big disclosure, give it a try.
