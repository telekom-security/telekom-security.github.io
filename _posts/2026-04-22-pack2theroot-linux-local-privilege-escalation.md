---
title: 'Pack2TheRoot (CVE-2026-41651): Cross-Distro Local Privilege Escalation Vulnerability'
header: 'Pack2TheRoot (CVE-2026-41651): Cross-Distro Local Privilege Escalation Vulnerability'
og_description: 'Pack2TheRoot (CVE-2026-41651) is a local privilege escalation (LPE) vulnerability that affects multiple Linux distributions in default installations.'
og_image: '/assets/images/Pack2TheRoot/Pack2TheRoot.png'
tags: ['advisories']
cwes: ['CWE-367 (Time-of-check Time-of-use (TOCTOU) Race Condition)']
affected_product: 'PackageKit'
vulnerability_release_date: '2026-04-20'
---



Today we publicly disclose a high-severity vulnerability (CVSS 3.1: 8.8) - in coordination with distro maintainers - that affects multiple Linux distributions in their default installations.
The Pack2TheRoot vulnerability can be exploited by any local unprivileged user to obtain root access on a vulnerable system. <!--more-->

The vulnerability lies in the [PackageKit daemon](https://github.com/PackageKit/PackageKit), a cross-distro package management abstraction layer.

The vulnerability enables an unprivileged attacker to install or remove system packages without authorization. This can be exploited to gain full root access or compromise the system in other ways.

The Pack2TheRoot (CVE-2026-41651) vulnerability was discovered by Deutsche Telekom's Red Team during targeted research into local privilege escalation vectors on modern Linux systems.
PackageKit as a candidate initially caught our attention when we observed that a `pkcon install` command could install a system package without requiring a password on a Fedora Workstation.
Starting in 2025, we began investigating whether this behavior could be abused to achieve arbitrary package installation.
By guiding the AI-assisted research into a specific direction (using Claude Opus by Anthropic) we were able to discover an exploitable vulnerability.
The finding was manually reviewed and verified before being responsibly reported to the PackageKit maintainers, who confirmed the issue and its exploitability.


### Which versions and systems are vulnerable? {#vulnerable-versions}

All PackageKit versions between `>= 1.0.2` and `<= 1.3.4` are vulnerable.
Since PackageKit 1.0.2 was released over 12 years ago, this leaves a broad attack surface across Linux distributions.
Exploitability has been explicitly tested and confirmed on the following distributions in default installations with `apt` and `dnf` package manager backends:

- Ubuntu Desktop 18.04 (EOL), 24.04.4 (LTS), 26.04 (LTS beta).
- Ubuntu Server 22.04 - 24.04 (LTS)
- Debian Desktop Trixie 13.4
- RockyLinux Desktop 10.1
- Fedora 43 Desktop
- Fedora 43 Server

It is reasonable to assume that all distributions that ship PackageKit with it enabled are vulnerable.
Since PackageKit is an optional dependency of the [Cockpit project](https://cockpit-project.org/), many servers with Cockpit installed might be vulnerable as well, including Red Hat Enterprise Linux (RHEL).

The vulnerability is fixed in PackageKit release 1.3.5 and distribution backports.
Updates should be available from today 2026-04-22 12:00 CEST.

### How to check if your system is vulnerable

It is not sufficient to simply `grep` through the process list, as PackageKit and Cockpit are not necessarily running as persistent processes as they can be activated on demand through D-Bus.
First check if PackageKit is installed on your system and compare it with [vulnerable versions](#vulnerable-versions), e.g.
- `dpkg -l | grep -i packagekit` or
- `rpm -qa | grep -i packagekit`

Note `grep`'s `-i` flag, as the package may be installed in camel case as `PackageKit`.

To check if the PackageKit daemon is available, run `systemctl status packagekit` or `pkmon`.
If `systemctl` shows it as `loaded` or `running` or the PackageKit monitor tools show transaction output, the daemon is active and your system is potentially exploitable if unpatched. 
For PackageKit `< 1.3.3` test `pkmon`, for versions `>= 1.3.3` use `pkgcli monitor` to test for output.

**Updated Packages**

Despite of the fixed release `1.3.5`, multiple Distributions released patched packages.
In the following, we link the Distros package overviews, that show Distro specific patched versions.

- Debian: [https://security-tracker.debian.org/tracker/CVE-2026-41651](https://security-tracker.debian.org/tracker/CVE-2026-41651)
- Ubuntu: [https://bugs.launchpad.net/bugs/cve/2026-41651](https://bugs.launchpad.net/bugs/cve/2026-41651)
- Fedora 42 - 44: Fixed in PackageKit-1.3.4-3 [https://koji.fedoraproject.org/koji/packageinfo?packageID=5206](https://koji.fedoraproject.org/koji/packageinfo?packageID=5206)



### Indicators of compromise (IOC) {#indicators-of-compromise}

Even though the vulnerability is reliably exploitable in seconds, it leaves traces that serve as a strong indicator of compromise.
After successful exploitation, the PackageKit daemon hits an assertion failure and crashes.
Systemd recovers the daemon on the next D-Bus invocation, preventing a denial-of-service, but the crash is observable in the system logs:

```
# journalctl --no-pager -u packagekit | grep -i emitted_finished
Apr 18 09:56:36 Rocky10 packagekitd[2082]: PackageKit:ERROR:../src/pk-transaction.c:514:pk_transaction_finished_emit: assertion failed: (!transaction->priv->emitted_finished)
Apr 18 09:56:36 Rocky10 packagekitd[2082]: Bail out! PackageKit:ERROR:../src/pk-transaction.c:514:pk_transaction_finished_emit: assertion failed: (!transaction->priv->emitted_finished)
```

### Technical Details {#technical-details}

The vulnerability is a time-of-check-time-of-use (TOCTOU) race condition in PackageKit's D-Bus transaction handling.

**PackageKit and Transaction Flags**

PackageKit is a D-Bus system service that runs as root and delegates authorization to [polkit](https://github.com/polkit-org/polkit). When a client wants to install a package, it creates a transaction object over D-Bus and calls a method such as `InstallFiles(flags, [path])`.

The `flags` parameter is a bitfield that controls the transaction's behavior. Certain flag values (such as `SIMULATE` and `ONLY_DOWNLOAD`) cause PackageKit to skip polkit authorization entirely, because the operations they represent are considered safe: they should never modify the system.

**The Root Cause**

The core issue is that PackageKit's transaction handler unconditionally overwrites the cached transaction flags on every `InstallFiles` call, without verifying the transaction's current state. There is no guard ensuring the transaction is still in its initial state. A second call on the same transaction can overwrite the flags even after the transaction has already been authorized and is running.

PackageKit's state machine does have a guard against backward state transitions, but it rejects them silently. The flag overwrite happens *before* the state transition is attempted, so the corrupted flags remain in effect while the transaction continues to run.

When the transaction is eventually executed, the scheduler reads the *current* value of the cached flags. If the safety flags have been stripped by a subsequent call, the backend performs a real operation instead of the originally authorized safe one.

**GLib Event Loop Ordering**

A key property that makes this exploitable is GLib's main loop priority system: D-Bus messages are dispatched at a higher priority than idle callbacks. The scheduler executes transactions through idle callbacks, which means any pending D-Bus message is *always* processed first. This creates a reliable window for the flag overwrite to land before the transaction actually executes.


#### Proof-of-Concept

We have developed a working proof-of-concept that reliably exploits this vulnerability to achieve root code execution from an unprivileged local user on default installations of various distributions. However, the PoC code is not being shared publicly at this time for obvious reasons.

![Proof-of-Concept Screenshot](/assets/images/Pack2TheRoot/pack2theroot-poc2.png){: .img-small }

### Credits

A huge thank you goes to PackageKit maintainer Matthias Klumpp ([@ximion](https://github.com/ximion)), for addressing this vulnerability quickly by creating a patch and for coordinating communication with the distribution maintainers.
The vulnerability has been found and reported by Deutsche Telekom's Red Team.
If you have questions regarding the vulnerability or are interested in our [security offerings](https://geschaeftskunden.telekom.de/business/loesungen/digitalisierung/cyber-security), including Red Team assessments, feel free to contact <span class="obf" data-obf="Y21Wa2RHVmhiVUIwWld4bGEyOXRMbVJs">[loading (JS)...]</span>.

### Timeline {#timeline}

- 2026-04-08: Private report of the vulnerability to Red Hat (through Fedora) and PackageKit project
- 2026-04-10: Acknowledgement of receipt and plausibility of the vulnerability by PackageKit maintainer
- 2026-04-13: First draft of private patch by PackageKit maintainer Matthias Klumpp ([@ximion](https://github.com/ximion))
- 2026-04-15: Informed Canonical about the issue
- 2026-04-15: Shared patch with Red Hat and Canonical
- 2026-04-19: Privately informed distribution vendors through [distros mailing list](https://oss-security.openwall.org/wiki/mailing-lists/distros), shared patch and publication date
- 2026-04-21: Reaffirmed the publication date with distribution maintainers 
- 2026-04-22: PackageKit patch release and public disclosure through [oss-security mailing list](https://www.openwall.com/lists/oss-security/2026/04/22/6) and this blog post.
- 2026-04-22: Got CVE-2026-41651 assigned
- 2026-04-23: Public exploit available on GitHub
- 2026-04-29: Updated blog article with technical details

### Advisories

- GitHub Security Advisory [GHSA-f55j-vvr9-69xv](https://github.com/PackageKit/PackageKit/security/advisories/GHSA-f55j-vvr9-69xv)
- [CVE-2026-41651](https://www.cve.org/CVERecord?id=CVE-2026-41651)

*The images in this article are free to use, as long as a reference to this blog post is provided.*
A [SVG version](/assets/images/Pack2TheRoot/Pack2TheRoot.svg) of the Pack2TheRoot Logo is also available.

<style>
.content {
    display: block;
    text-align: justify;
}
#h4 {
    font-size: 1em !important;
}

.img-small {
  width: 80%;
  max-width: 100%;
  height: auto;
}
</style>

<script>
document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => {
    document.querySelectorAll(".obf").forEach(el => {
      const encoded = el.dataset.obf;
      try {
        const decoded = atob(atob(encoded));
        el.textContent = decoded;
      } catch (e) {
        el.textContent = "unknown";
      }
    });
  }, 1500); // 1.5s delay
});
</script>
