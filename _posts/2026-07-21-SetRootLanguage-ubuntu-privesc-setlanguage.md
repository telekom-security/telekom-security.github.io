---
title: 'SetRootLanguage: Local privilege escalation in Ubuntu via AccountsService'
header: 'SetRootLanguage: Local privilege escalation in Ubuntu via AccountsService'
og_description: "Deutsche Telekom's Red Team discovered a two-bug chain in Ubuntu to gain root privileges via AccountsService."
og_image: "/assets/images/SetRootLanguage/SetRootLanguage-og.png"
tags: ['advisories', 'writeup']
obfuscated_contact: true
cwes: ['CWE-271: Privilege Dropping / Lowering Errors', 'CWE-78: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)', 'CWE-20: Improper Input Validation']
affected_product: 'AccountsService, language-selector'
vulnerability_release_date: '2026-07-21'
cve: ['CVE-2026-61897', 'CVE-2026-61898']
---

A two-bug chain in Ubuntu's AccountsService language update path allows any local user to obtain local root access. We call the vulnerability chain "SetRootLanguage" because a single call to the `SetLanguage` D-Bus method is all it takes to end up with root. The only prerequisite is that at least one non-English language pack is installed on the system.
This blog post is a continuation of our previous research on local privilege escalation vulnerabilities in userland applications on Linux-based operating systems.
<!--more-->
The discovery came from targeted research into privilege escalation vectors in the Ubuntu desktop stack. The vulnerabilities were responsibly disclosed to Canonical and assigned CVE IDs. Ubuntu security advisories for all affected releases were published on the coordinated release date of 2026-07-21 16:00 UTC.


### Affected versions, fixes and mitigations {#affected-versions}

The following table lists the affected Ubuntu distributions as of the coordinated release date:

| Ubuntu Release | Codename | Status | Fixed package |
|----------------|----------|--------|---------------|
| 26.10 | Stonking | Fix Released | accountsservice 23.13.9-8ubuntu7, libaccountsservice0 23.13.9-8ubuntu7 |
| 26.04 LTS | Resolute | Fix Released | accountsservice 23.13.9-8ubuntu5.2, libaccountsservice0 23.13.9-8ubuntu5.2 |
| 24.04 LTS | Noble | Fix Released | accountsservice 23.13.9-2ubuntu6.1, libaccountsservice0 23.13.9-2ubuntu6.1 |
| 22.04 LTS | Jammy | Fix Released | accountsservice 22.07.5-2ubuntu1.6, libaccountsservice0 22.07.5-2ubuntu1.6 |
| 20.04 LTS | Focal | Fix Released (ESM) | accountsservice 0.6.55-0ubuntu12~20.04.7+esm1 (Ubuntu Pro) |
| 18.04 LTS | Bionic | Fix Released (ESM) | accountsservice 0.6.45-1ubuntu1.3+esm2 (Ubuntu Pro) |
| 16.04 LTS | Xenial | Fix Released (ESM) | accountsservice 0.6.40-2ubuntu11.6+esm2 (Ubuntu Pro) |
| 14.04 LTS | Trusty | Fix Released (ESM) | accountsservice 0.6.35-0ubuntu7.3+esm4 (Ubuntu Pro) |

### Fix and mitigation {#mitigation}

Canonical published Ubuntu Security Notices covering all affected releases on 2026-07-21:
- [USN-8580-1](https://ubuntu.com/security/notices/USN-8580-1): Ubuntu 26.10, 26.04 LTS, 24.04 LTS, 22.04 LTS
- [USN-8580-2](https://ubuntu.com/security/notices/USN-8580-2): Ubuntu 20.04 LTS, 18.04 LTS, 16.04 LTS, 14.04 LTS (requires Ubuntu Pro)

Apply the available security updates immediately:

```bash
sudo apt-get update && sudo apt-get install --only-upgrade accountsservice libaccountsservice0
```

If updates cannot be applied immediately, note that the vulnerable branch in `set-language-helper` is only reached when at least one non-English language pack is installed. Removing non-English language packs prevents the vulnerable code path from being triggered, but is not a reliable long-term safeguard and should not be substituted for patching.



## A language request that speaks root

During targeted local privilege escalation research, we turned our attention to the Ubuntu desktop stack, specifically the D-Bus services that manage user account settings. [AccountsService](https://www.freedesktop.org/wiki/Software/AccountsService/) is a daemon that lets desktop sessions read and modify account properties such as the display name, icon, and preferred language. It ships and runs by default on Ubuntu as root.

Root process, shell scripts, user-controlled input. We found the collision we were looking for.
The vulnerability is a two-bug chain that allows any local user to obtain a root shell with a single D-Bus call. The first bug is an incomplete privilege drop in AccountsService, which sets only the effective UID to the unprivileged user before launching Ubuntu language helper scripts. The second bug is a shell injection by attacker controlled input.
However, a successful exploitation requires that at least one non-English language pack is installed on the system.


### Proof-of-Concept {#proof-of-concept}

Currently we do not share detailed technical information on the exploitation or a proof-of-concept (PoC) for the vulnerabilities, as this could be misused by malicious actors.
We plan to update this blog post with a technical write-up at a later time.

![SetRootLanguage PoC](/assets/images/SetRootLanguage/SetRootLanguage-poc.png){: .img-small }

### Advisories {#advisories}

- [CVE-2026-61897](https://ubuntu.com/security/CVE-2026-61897): AccountsService sets only effective UID before launching Ubuntu language helpers, leaving real UID as root and allowing any subsequently spawned shell to regain full root credentials
- [CVE-2026-61898](https://ubuntu.com/security/CVE-2026-61898): Ubuntu language helper scripts embed unsanitized attacker-controlled input, enabling shell injection via the `sed` execute flag (`/e`)

### Credits

The vulnerability chain was discovered by Deutsche Telekom's Red Team during targeted research into local privilege escalation vectors on modern Linux systems.

If you have questions regarding this research or are interested in our [security offerings](https://telekom.de/security), including Red Team assessments, feel free to contact <span class="obf" data-obf="Y21Wa2RHVmhiVUIwWld4bGEyOXRMbVJs">[loading (JS)...]</span>.

### Timeline {#timeline}

- 2026-06-23: Initial vulnerability report to Canonical/Ubuntu Security Team.
- 2026-06-24: Acknowledgment of receipt and initial triage.
- 2026-07-13: [CVE-2026-61897](https://ubuntu.com/security/CVE-2026-61897) and [CVE-2026-61898](https://ubuntu.com/security/CVE-2026-61898) have been assigned to the issues.
- 2026-07-21: Coordinated responsible disclosure: Canonical releases patches and this blog post is published.
- 2026-07-27: Added fixed package for Ubuntu 26.10 (stonking)

<link rel="stylesheet" href="{{ "/css/setrootlanguage.css" | relative_url }}">
