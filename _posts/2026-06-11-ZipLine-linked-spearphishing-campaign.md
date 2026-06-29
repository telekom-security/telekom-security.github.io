---
title: 'ZipLine-linked spearphishing campaign uses PowerShell backdoor and Cloudflare Tunnel'
header: 'ZipLine-linked spearphishing campaign uses PowerShell backdoor and Cloudflare Tunnel'
tags: ['ThreatIntel']
---

Telekom Security investigated a spearphishing campaign targeting organizations in several European countries. The campaign ultimately enables follow-on activity that, in at least one observed case, led to the deployment of Qilin ransomware.
We are aware of multiple affected companies across different countries, most of them located in Austria. Not all of these organizations were encrypted, but at least one became a victim of Qilin ransomware.
We assess this activity to be related to the [ZipLine campaign](https://research.checkpoint.com/2025/zipline-phishing-campaign/), which was uncovered by Check Point Research in August 2025. While there are some differences in the current activity, the overall tradecraft shows multiple similarities, as described throughout this blog post. <!--more-->

For initial access, the attackers send targeted spearphishing emails containing a fake job offer and impersonating a legitimate recruiting agency. If the recipient shows interest, the attackers send a follow-up mail containing a URL that leads to the download of malware.
The delivered malware is a `.LNK` file containing embedded PowerShell code. It installs a small PowerShell backdoor that allows the attacker to execute arbitrary commands on the affected system and stage additional payloads.
We also observed the actor using Cloudflare Tunnel to hide potentially suspicious network traffic at compromised environments.

## Attack description

### Spearphishing emails
The actor sent well-crafted emails to a small number of recipients. The initial email did not contain any malicious attachment or link. Instead, it contained German-language text in which the sender claimed to represent a recruiting agency offered information about a potential interesting job opportunity.

![Initial email with job offer](/assets/images/zipline/Spearphising 1.png){: .img-small }
*Figure 1: Initial email with job offer*

The domain `alpentalent[.]at`, used in this case, is one of several domains created by the attacker for this stage of the campaign. In addition to domains already known from earlier activity, we identified at least one additional domain associated with this campaign.

If victims visited the website, they were presented with a complete website designed to resemble a legitimate recruiting agency. The second domain we observed in this campaign, `steinersearch[.]at`, followed the same pattern. The actor appears to reuse an HTML template with only minor variations. The page structure and most of the text are similar across domains, while the visual design differs slightly.

![Alpentalent fake website](/assets/images/zipline/alpen.png){: .img-small }
*Figure 2: Alpentalent fake website*

![SteinerSearch fake website](/assets/images/zipline/steiner.png){: .img-small }
*Figure 3: SteinerSearch fake website*

CERT.at recently [reported](https://www.cert.at/de/aktuelles/2026/5/zipline-qilin-raas-update) multiple additional domains, indicating the campaign is still ongoing.

Once the victim replied to the email and expressed interest in receiving more information about the job opportunity, the actor sent a follow-up message. This message attempted to trick the victim into downloading a ZIP archive from a `herokuapp[.]com` subdomain.

### Backdoor
The downloaded ZIP archive follows the naming pattern:
```
Dienstangebot_<LAST NAME>_<FIRST LETTER FIRST NAME>_<DATE>.zip
``` 
Following this pattern, we leveraged third-party telemetry to identify multiple files associated with the campaign, indicating with moderate confidence that the activity most likely began in mid-March 2026.

The archive contains two decoy Microsoft Word documents and a malicious `.LNK` file using a `.docx.lnk` double extension. In our case, the decoy documents contained information about alleged job opportunities at the German company Rossmann.

![Decoy document with job information](/assets/images/zipline/Ross.png){: .img-small }
*Figure 4: "Become part of Rossmann Austria" - decoy document with job information*

Unlike the `.LNK` file, the two Microsoft Word documents do not contain malware. They are used solely as decoys to distract the victim.

The `.LNK` file executes a short but obfuscated PowerShell script. After deobfuscation, the script performs the following actions:

1. Searches for the original ZIP archive in these Locations: 
   - `Downloads`
   - `Documents`
   - `Desktop`

   If the ZIP archive does not exist in one of these locations, or if the victim saved the downloaded file elsewhere, the malware stops execution.
2. Performs an AMSI bypass by replacing the `AmsiUtils.ScanContent` method pointer with a method pointer to a benign PowerShell method created solely for this purpose.
3. Reads the original downloaded ZIP archive as a raw file, searches for the marker string `SwbWu`, and extracts another PowerShell snippet hidden after this marker. The archive is not parsed as a ZIP container at this stage. The hidden snippet can be viewed and extracted with a hex editor.
   - Executes the extracted PowerShell snippet.

![Hex view of the ZIP archive](/assets/images/zipline/hexedit-2.png){: .img-small }
*Figure 5: Hex view of the ZIP archive. The marker string and PowerShell code are highlighted.*

The content hidden inside the ZIP archive is the actual backdoor. Its capabilities are limited, but sufficient for an attacker to steal data or download additional payloads, or execute follow-on malware such as ransomware.

The backdoor performs the following actions:

1. Extracts the contents of the original ZIP archive to 

   ```
   %LOCALAPPDATA%\<ARCHIV FILENAME>
   ```

2. Opens the decoy document `ROSSMANN_Kandidatenbrochure.docx` to distract the victim.
3. Creates a scheduled task that runs every day at 11:00. This task executes the `.LNK` file and serves as the persistence mechanism. The name of the scheduled task is 

   ```
   <VICTIM-ID>c582
   ```

4. Creates a victim fingerprint:
   - Victim ID: CRC32 of the value from

     ```
     HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId
     ```

   - Campaign ID: CRC32 of the original ZIP archive
5. Creates a Mutex named:

   ```
   Global\<VictimID>
   ```

6. Constructs a domain name later used as the command and control server for the backdoor. This domain is also a `herokuapp[.]com`-subdomain.
7. Communicates with the C2 server using the following URL pattern: 

   ```
   https://*[.]herokuapp[.]com/<VictimID>c582<xor_hex(VictimID, "[]0")><unix_timestamp_hex><random_hex>
   ```

8. Requests this URL every four to six minutes. The HTTP response is decrypted using XOR with the Victim ID as the key and then evaluated. 
9. Uses the following User-Agent string for C2 communication: 

   ```
   Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
   ```

   This is a valid User-Agent string for Google Chrome on Microsoft Windows 10. Chrome version 140 was published in September 2025.

The backdoor supports three C2 command types:

| Command            | Description                                           |
| ------------------ | ----------------------------------------------------- |
| `#KILL`            | Deletes the scheduled task and the malware directory. |
| `#HOST#<NEW_HOST>` | Defines a new C2 server.                              |
| Any other response | Interpreted and executed as PowerShell code           |

### Cloudflare Tunnel
After the backdoor has been installed, the actor can execute arbitrary PowerShell code on the affected system. This creates opportunities for data theft, payload deployment, lateral movement, and ransomware staging.

In this campaign, we observed the actor installing [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/) to hide suspicious network traffic and enable remote access.

Cloudflare Tunnel is a legitimate technology used to expose local services such as HTTP, SSH, or Remote Desktop via the Cloudflare network. It can also be used to make private networks accessible through a tunnel connection, for example by using WARP routing. In an intrusion context, this gives an attacker several options to interact with compromised systems while blending into traffic to a legitimate cloud provider.

For this setup, the attacker only needs the `cloudflared` executable, which is the server-side daemon used to connect a local service to the Cloudflare network.

In the observed case, the following artifacts were left on disk:
```
\Users\<USERNAME>\AppData\Local\Temp\cf
```
The directory contained:
- `cloudflared.exe`
- `cert.pem`, used for authentication
- `config.yaml`, the tunnel configuration file 
- `<TUNNEL ID>.json`, the tunnel credentials file, perhaps multiple of them
- An error log file, if errors occurred

These artifacts are valuable for forensic analysis, as they can help determine how the tunnel was configured and how it may have been used by the actor.

## Conclusion
The observed activity demonstrates how a convincing spearphishing lure can develop into a ransomware-relevant intrusion path. The actor uses fake recruiting agencies, tailored job offers, decoy documents, and a lightweight PowerShell backdoor to establish initial access and maintain persistence.

While the malware itself is not complex, it provides the attacker with enough flexibility to execute arbitrary PowerShell code, deploy additional tools, and prepare follow-up activity. In at least one observed case, this attack chain ultimately led to Qilin ransomware deployment.

The campaign also shows the continued abuse of legitimate cloud services and tunneling technologies. Heroku-hosted infrastructure and Cloudflare Tunnel can make malicious activity harder to distinguish from normal cloud traffic, which increases the importance of behavioral detection and forensic artifact analysis.

Defenders should monitor for PowerShell execution from shortcut files, unusual scheduled tasks, unexpected `cloudflared` executions, and network connections to known attacker-controlled cloud infrastructure. The following section provides additional details to support hunting, investigation, and response.

## Appendix

### IOCs

| Type              | Value                                                                                                             | Description                                                 |
| ----------------- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| Domain            | `alpentalent[.]at`                                                                                                | Phishing-Domain                                             |
| Domain            | `steinersearch[.]at`                                                                                              | Phishing-Domain                                             |
| Domain            | `headmatch[.]at`                                                                                              | Phishing-Domain                                             |
| Domain            | `vertrag-hm-ref3154-7e89a2ad95ad[.]herokuapp[.]com`                                                               | ZIP archive download domain                                 |
| Domain            | `sched-729-fdfd12d20ba1[.]herokuapp[.]com`                                                                        | C2 domain                                                   |
| Domain            | `assetscrm-04-6532d8371b2a.herokuapp.com`                                                                         | C2 domain                                                   |
| Domain            | `erpapp-091-e00eb01e7fba.herokuapp.com`                                                                         | C2 domain                                                   |
| Domain            | `clientportal-43-98f1d0f4b8d9.herokuapp.com`                                                                         | C2 domain                                                   |
| Domain            | `erpapp-071-00266c67b940.herokuapp.com`                                                                         | C2 domain                                                   |
| User-Agent string | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36` | User-Agent string used for C2 communication                 |
| Directory         | `\Users\<USERNAME>\AppData\Local\Temp\cf`                                                                         | Directory which contains Cloudflare Tunnel files            |
| SHA-256           | `4578bc4b0b5eab3ac6e38d71bc1a086593b118c8bb221161d3fd27c5f5d00ea6`                                                | Decoy document `2026_NDA_Datenschutzrichtlinie.docx`        |
| SHA-256           | `ee6c8422e4e723fe408ef6bbacfa852ae372e99ddf79e2fe38920017ec5e7674`                                                | Decoy document `ROSSMANN_Kandidatenbrochure.docx`           |
| SHA-256           | `1067ffcb2b3f50d3769d05389e5d384abccc274c5433ee0fb27f6616dbf7d2c6`                                                | Powershell script for tunnel start, `cloudflared-start.ps1` |
| SHA-256           | `e00a9e9fed12f8a8f5703539c4662750dd5472d35c16dcbbdc5869f3fe5e238b`                                                | Cloudflare tunnel executable, `cloudflared.exe`             |
| File name         | `Dienstangebot_<LAST NAME>_<FIRST LETTER FIRST NAME>_<DATE>.zip`                                                  | Naming pattern of downloaded ZIP archive                    |
| Scheduled Task    | `<VICTIM-ID>c582`                                                                                                 | Backdoor persistence                                        |
| Mutex             | `Global\<VictimID>`                                                                                               | Mutex created by backdoor                                   |
| Email address     | `elisabeth.muehlbacher@steinersearch.at`                                                                          | known sender address                                        |
| Email address     | `marlies.hoermann@steinersearch.at`                                                                               | known sender address                                        |
| Email address     | `caroline.hoeller@steinersearch.at`                                                                               | known sender address                                        |
| Email address     | `maria.schroeder@alpentalent.at`                                                                                  | known sender address                                        |
| Email address     | `daniela.weiss@alpentalent.at`                                                                                    | known sender address                                        |
| Email address     | `michaela.jaeger@alpentalent.at`                                                                                  | known sender address                                        |
| Email address     | `petra.schoepf@alpentalent.at`                                                                                    | known sender address                                        |
| Email address     | `anna.gruber@headmatch.at`                                                                                    | known sender address                                        |

Please also visit the [CERT.at website](https://www.cert.at/de/aktuelles/2026/5/zipline-qilin-raas-update) for additional IOCs.

### Threat Hunting

The following queries for Microsoft Defender can be used to identify possible affected systems:
```js
// Search for spearphishing emails:
let phishing_domains = dynamic(["steinersearch.at", "alpentalent.at", "headmatch.at"]); 
EmailEvents
| where (SenderFromDomain in (phishing_domains) or RecipientDomain in (phishing_domains)) 
or Subject contains " - Jobangebot: "

// Search for ZIP archives:
DeviceProcessEvents //DeviceFileEvents
| where FileName startswith "Dienstangebot_" and FileName endswith "-26.zip"

//Search for malicious URLs in Emails:
EmailUrlInfo
| where Url contains "herokuapp.com" and Url contains "vertrag"

//Search for Cloudflare tunnel software network communication:
DeviceNetworkEvents
| where InitiatingProcessFileName has "cloudflared"
```

### MITRE ATT&CK Mapping

| ID                                                          | Name                               |
| ----------------------------------------------------------- | ---------------------------------- |
| [T1573](https://attack.mitre.org/techniques/T1573/)         | Encrypted Channel                  |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols                      |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell                         |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Malicious File                     |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task                     |
| [T1027](https://attack.mitre.org/techniques/T1027/)         | Obfuscated Files or Information    |
| [T1090.002](https://attack.mitre.org/techniques/T1090/002/) | External Proxy                     |
| [T1105](https://attack.mitre.org/techniques/T1105/)         | Ingress Tool Transfer              |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Spearphishing Link                 |
| [T1082](https://attack.mitre.org/techniques/T1082/)         | System Information Discovery       |
| [T1041](https://attack.mitre.org/techniques/T1041/)         | Exfiltration Over C2 Channel       |
