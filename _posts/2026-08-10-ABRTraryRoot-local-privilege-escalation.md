---
title: 'ABRTraryRoot: Local privilege escalation in Red Hat distributions'
header: 'ABRTraryRoot: Local privilege escalation in Red Hat distributions'
og_description: 'A chain of five bugs in ABRT (Automatic Bug Reporting Tool) allows achieving root code execution.'
og_image: "/assets/images/ABRTraryRoot/abrt-og.png"
tags: ['advisories', 'writeup']
obfuscated_contact: true
cwes: ['CWE-367 (Time-of-check Time-of-use (TOCTOU) Race Condition)', 'CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)', 'CWE-59: Improper Link Resolution Before File Access (Link Following)', 'CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component (Injection)']
affected_product: 'ABRT'
vulnerability_release_date: '2026-06-15'
cve: ['CVE-2026-54228', 'CVE-2026-54229', 'CVE-2026-54230', 'CVE-2026-54231']
---

A chain of five bugs in ABRT allows any unprivileged local user to write attacker-controlled content into the root crontab, resulting in arbitrary command execution as root.
We call the vulnerability chain "ABRTraryRoot" because it abuses ABRT's crash handling pipeline to achieve arbitrary root code execution. The full chain requires no user interaction beyond triggering a crash and runs in under 90 seconds, with the majority of that time just waiting for `crond` to execute the planted payload.
This blog post is a continuation of our previous research on local privilege escalation vulnerabilities in userland applications on Linux-based operating systems ([Pack2TheRoot]({% link _posts/2026-04-22-pack2theroot-linux-local-privilege-escalation.md %}) and [SetRootLanguage]({% link _posts/2026-07-21-SetRootLanguage-ubuntu-privesc-setlanguage.md %})).
<!--more-->
The discovery is the result of targeted research into ABRT's crash handling pipeline and its interaction with D-Bus APIs. The vulnerabilities were responsibly disclosed to Red Hat and assigned CVE IDs to them.
Red Hat has acknowledged the vulnerabilities and published updates for supported Fedora releases on 2026-08-03.


### Affected versions, fixes and mitigations {#affected-versions}

The following lists the affected components and versions that were tested during the research. Other versions may be affected as well.

| Component | Version |
|-----------|---------|
| OS | Fedora 43/44 |
| ABRT | 2.17.8-3.fc44 |
| libreport | 2.17.15-10.fc44 |
| SELinux | Enforcing |

The exploit was developed and confirmed on Fedora 44 using an unprivileged user. Red Hat Enterprise Linux is also affected, see the table below and Red Hat's advisories for details.

### Fix and mitigation {#mitigation}

Updates are available for supported Red Hat Enterprise Linux and Fedora releases (see table below). ABRT was deprecated in RHEL 8 and is no longer shipped in RHEL 9 or later.

### Releases Overview

| Release | Status |
|---------|--------|
| Fedora 43 | Fix available in [2.17.9-1.fc43](https://packages.fedoraproject.org/pkgs/abrt/abrt/fedora-43-updates.html) |
| Fedora 44 | Fix available in [2.17.9-1.fc44](https://packages.fedoraproject.org/pkgs/abrt/abrt/fedora-44-updates.html) |
| Fedora Rawhide | Fix available in [2.17.9-1.fc45](https://packages.fedoraproject.org/pkgs/abrt/abrt/fedora-rawhide.html) |
| Red Hat Enterprise Linux 6 | Out of support scope |
| Red Hat Enterprise Linux 7 | Fixes available |
| Red Hat Enterprise Linux 8 | Fixes available |
| Red Hat Enterprise Linux 9+ | Not affected (ABRT not shipped) |

### Recent Activity

If you're running ABRT and don't strictly need it, the safest move is to turn it off:

```bash
systemctl disable --now abrtd.service abrt-journal-core.service abrt-oops.service abrt-xorg.service
```

On Fedora, consider switching to `systemd-coredump` for crash handling. ABRT is being phased out in its favor anyway, and `systemd-coredump` doesn't suffer from the same architectural issues. If removing ABRT isn't an option, restrict local access to affected systems, since the entire chain requires a local user account to exploit.



## Crashing into privilege

During targeted local privilege escalation research, we turned our attention to [ABRT](https://github.com/abrt/abrt), the Automatic Bug Reporting Tool that ships by default on Fedora. ABRT monitors for application crashes, collects diagnostic data, and files bug reports. Sounds harmless, right?

What caught our eye was the architecture: when a crash occurs, ABRT spawns event handler shell scripts running as **root** that process files in a dump directory. If an attacker could influence *what* those scripts write and *where* they write it... then it's game over.

So, it all started with a segfault. On purpose.

### Understanding the crash pipeline

ABRT runs two system services as root. When an application crashes, ABRT picks up the crash dump and runs a series of shell scripts (as root) to collect system information (hardware details, log entries, etc.) and store them in a "dump directory".

The key insight: these root-owned shell scripts write files into the dump directory using plain shell redirections (`>`). And while they're doing that, there are D-Bus APIs that let unprivileged users interact with the same directory.

We thought: if we can redirect one of those root-owned shell scripts to write through a symlink pointing at the root crontab (`/var/spool/cron/root`), we own the box. But getting there required chaining five separate bugs.

### The Bug Chain {#bug-chain}

Five bugs. Individually, each one is a nuisance at best. Chained together, they hand you a root shell. Here's how we pieced it together.

#### Sneaking files into the dump directory (CVE-2026-54228)

The first thing we noticed: between the moment ABRT creates a dump directory and the moment event scripts start processing it, there's a window of several seconds where nothing is locked down. During that gap, any local user can call `SetElement` over D-Bus to drop arbitrary files into the directory. The only check? That the crash "belongs" to you, which it does, because you triggered it.

So now we can plant files in the dump directory before anyone else touches them. Interesting. Let's see what we can do with that.

#### Faking a legitimate crash

Here's the first roadblock: ABRT validates whether the crashed binary belongs to an installed system package. Our custom crashing binary? Not a package. Crash report deleted. Chain over... unless we lie about it.

Using that first bug, we race to set the `component` field to "coreutils" before validation kicks in. ABRT checks, sees a known package name, shrugs, and moves on. Our crash report survives.

#### Pulling the rug mid-flight (CVE-2026-54229)

This is the most surprising one. There's a D-Bus method called `ChownProblemDir` that changes the ownership of a dump directory to the requesting user. Perfectly safe... except for one thing: due to a locking oversight, it succeeds **even while event scripts are actively running inside that directory**.

Think about what that means. Root-owned shell scripts are happily executing, writing files, doing their thing. Meanwhile, we just took ownership of the directory they're working in. We can now delete files, create symlinks, do whatever we want and the root process keeps running, completely unaware that the ground shifted beneath it.

#### Following the symlink to root's crontab (CVE-2026-54230)

ABRT's internal C code is actually careful about symlinks as it refuses to follow them when writing files. But the event handler scripts? They're shell scripts. They write output with plain old `>` redirections. And shell redirections follow symlinks without a second thought.

So after we take ownership of the dump directory, we delete one of the files the event script is about to write (`var_log_messages`) and replace it with a symlink pointing at `/var/spool/cron/root`. When the root shell process gets around to writing that file, it happily follows our symlink and dumps content straight into the root crontab.

Now we just need to control *what* gets written.

#### Poisoning the well (CVE-2026-54231)

The event script that writes `var_log_messages` collects recent journal entries related to the crashed process. The journal. Which any user can write to.

Before triggering the crash, we stuff the system journal with log messages containing an embedded cron job. The trick is a newline character inside the log message. It causes our payload to land on its own line in the output. `crond` is forgiving: it ignores lines it can't parse and executes the ones it can.

One minute later, `crond` picks up the new entry. A SUID root shell appears. Game over.

### Putting it all together

The full attack plays out in about 90 seconds — most of which is just waiting for `crond` to tick.

First, we build a small binary that logs a cron payload into the system journal and then crashes itself. We run it a few times to seed the journal with our malicious entries. Then we trigger ABRT by crashing the binary one last time.

The moment ABRT creates the dump directory, we race to set the `component` field to "coreutils" before validation runs. Once the crash survives that check, we call `ChownProblemDir` to yank ownership away while the event scripts are still running. Now we own the directory. We delete `var_log_messages` and drop a symlink to `/var/spool/cron/root` in its place.

The root event script, still chugging along, writes our poisoned journal entries through the symlink and straight into the root crontab. Within a minute, `crond` executes our payload and creates a SUID root shell. Done.

The actual race window is roughly 64ms wide. We win it reliably by flooding the journal beforehand — this slows down one of the event script's `journalctl` queries just enough to keep the window open.

### But what about hardening?

Fedora has a solid stack of mitigations deployed. Surely one of them catches this? We checked. None of them do.

`ProtectSystem=full` shields `/usr`, `/boot`, and `/etc` — but `/var/spool/cron/` sits outside that perimeter. `PrivateTmp=true` isolates `/tmp`, which doesn't matter because we're writing to the cron spool, not tmp. SELinux is enforcing, but the event script's domain is effectively unconfined and happily writes to the cron spool. `NoNewPrivileges=yes` prevents ABRT's own children from gaining privileges through SUID — but `crond` is a completely separate service that creates our SUID binary independently.

Every mitigation covers a different surface. None of them overlap on the path we're taking. Defense in depth is effective only when the individual layers address the same attack paths — here, each layer guards a different perimeter, leaving this one uncovered.

### Proof-of-Concept {#proof-of-concept}

The exploit consists of a Python script that orchestrates the full chain and a small C helper binary that injects the cron payload into the system journal before crashing. The full chain executes in under 90 seconds (mostly waiting for crond's one-minute tick) and produces a SUID root shell. The PoC code is not being shared publicly at this time.
However, the following screenshot shows the final result: a SUID root shell created by our cron payload, which was written into the root crontab by the ABRT event scripts.
![ABRTraryRoot PoC](/assets/images/ABRTraryRoot/ABRTraryRoot.png){: .img-small }

### Advisories {#advisories}

- [CVE-2026-54228](https://access.redhat.com/security/cve/cve-2026-54228): TOCTOU race condition in abrt-dbus SetElement allows arbitrary file writes to dump directories
- [CVE-2026-54229](https://access.redhat.com/security/cve/cve-2026-54229): ChownProblemDir succeeds during active post-create event processing due to inadequate locking
- [CVE-2026-54230](https://access.redhat.com/security/cve/cve-2026-54230): Event handler scripts follow symlinks when writing output files, allowing arbitrary file overwrites
- [CVE-2026-54231](https://access.redhat.com/security/cve/cve-2026-54231): Unsanitized systemd journal content written to dump directory files enables content injection

### Credits

The vulnerability chain was discovered by Deutsche Telekom's Red Team during targeted research into local privilege escalation vectors on modern Linux systems, assisted by Claude Code with model Opus 4.6.

If you have questions regarding this research or are interested in our [security offerings](https://geschaeftskunden.telekom.de/business/loesungen/digitalisierung/cyber-security), including Red Team assessments, feel free to contact <span class="obf" data-obf="Y21Wa2RHVmhiVUIwWld4bGEyOXRMbVJs">[loading (JS)...]</span>.

### Timeline {#timeline}

- 2026-05-04: Initial vulnerability report to Red Hat Security Team.
- 2026-05-06: Acknowledgment of receipt and initial triage.
- 2026-06-12: Red Hat confirms the vulnerabilities and publishes CVE IDs.
- 2026-06-15: Requested patch status update from Red Hat. Red Hat referred to the publicly available Bugzilla reports.
- 2026-08-03: Red Hat publishes updates for Fedora
- 2026-08-10: Publication of this blog post.


<link rel="stylesheet" href="{{ "/css/abrtraryroot.css" | relative_url }}">
