---
title: Peripheral Sight - Red Teaming with printer CVE
description: Discovery of printer CVE during Red Team assessment
header: Peripheral Sight - Red Teaming with printer CVE
tags: ['advisories']
cwes: ['(Possible) Exposure of Sensitive Information to an Unauthorized Actor (CWE-200)']
affected_product: 'Certain HP LaserJet Pro Printers'
vulnerability_release_date: '2024-05-23'
---

In a red team engagement, anything can be a target, and depending on what has already been looted (or not), everything *will* be a target - even as a form of desperation.
In this stage of an engagement, a red team member may have to broaden their vision and should also bring peripherals into their scope, as they may also contain valuable information or loot.
This happened during a red team engagement with the DT Security Red Team, which resulted in finding juicy information through a previously unknown CVE on an HP Printer.<!--more-->&nbsp;


### Why target a printer?

As mentioned before, depending on how hardened the infrastructure may be, finding good loot for further access to the network may be scarce. The idea of targeting a printer revolves around the fact that multifunctional devices may resolve user accounts via `ldap` and send their mail via `smtp`, authenticating with at least a service account.

![mfp_as_target](/assets/images/peripheral_sight_MFPAsTarget.svg)


### What actually happened?

At first, during a red team assumed breach engagement, nothing of significant value was found on the internal network - services were all authenticated through Microsoft-SSO or other well-established OpenID Connect solutions (all patched and up to date).

Being frustrated and grasping onto every straw there was, the red team eventually came upon a multifunctional office printer shared by every worker in the remote office.

A detailed port scan revealed the typical open ports `80/443` and `9100`. Since connecting to port `9100` revealed nothing of interest, the team proceeded onto the printer's built-in web server.

#### LDAP or Mail?

When clicking through the web interface, nothing concerning `ldap` resolution was found, but it was discovered that the mail functionality was configured with a `scan@xxx.com` user!

![Scan2Mail](/assets/images/peripheral_sight_scan2mal.png)

Finally, something that might be of value - so of course the team attempted to edit the settings to see whether information regarding the scan account could be extracted.
The edit page revealed the target SMTP-server, username and a password field:

![SettingsPage](/assets/images/peripheral_sight_settingsPage.png)

Hoping that the web interface may disclose the password in any way was naturally...

![ContentPasswordField](/assets/images/peripheral_sight_contentPWField.png)

... not crowned with success. =(

#### The simple idea...

So the printer did not disclose the password via the web interface... But can we *only* change the remote SMTP server address while retaining all the other information including the unkown password stored in the printer?

We tried and:

![InboundSMTP](/assets/images/peripheral_sight_inboundSMTP.png)

It worked! We could change the target SMTP and still retain the `user:password` already stored on the printer, resulting in a full disclosure of the credentials when run against a self-hosted `plain`-authenticated SMTP server (as shown above).

-> So another question remains: Can anybody change these settings? Apparently not, as admin access is required, but the interface does not restrict you if it is configured without authentication or has default credentials.

#### Was it worth it?

Without disclosing too much confidential information, yes it was - and it led to the full compromise of a major business service the client offered. =)

### The conclusion

Broadening your vision in a red team engagement may not only reveal new targets leading to a compromise of a service, but it can also end up with finding a CVE in a multifunctional printer.

Furthermore, restricting service accounts to their apparent use should be a given and should not be circumvented because some functions are convenient to use (disabling the whole concept).


### References

- HP: [https://support.hp.com/us-en/document/ish_10643804-10643841-16/hpsbpi03941](https://support.hp.com/us-en/document/ish_10643804-10643841-16/hpsbpi03941)
- Simple PoC to dump credentials: [https://github.com/petermueller-T/PoCs/blob/main/python/simple_smtp_server.py](https://github.com/petermueller-T/PoCs/blob/main/python/simple_smtp_server.py)

### Timeline

* **2024-01-02:** Reported to Vendor
* **2024-05-23:** Vendor has released the security bulletin with new firmware.
* **2024-07-04:** This blog post was published.

### Credits

* Peter Müller ([peter.mueller37@telekom.de](mailto:peter.mueller37@telekom.de))