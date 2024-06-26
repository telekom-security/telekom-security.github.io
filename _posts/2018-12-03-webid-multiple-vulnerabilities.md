---
title:  WeBid Directory Traversal, Blind SQL Injection and XSS
description: Advisory for WeBid <= Version 1.2.2
header: WeBid Directory Traversal, Blind SQL Injection and XSS
tags: ['advisories']
cwes: ['SQL Injection (CWE-89)', 'Cross-site Scripting (CWE-79)', 'Path Traversal (CWE-22)']
affected_product: 'WeBid Directory'
vulnerability_release_date: '2018-12-03'
---
Multiple vulnerabilities were identified in version 1.2.2 of the popular "WeBid" open source auction system. Patches for all three vulnerabilities are available in their GitHub, and will be included in the next release.

<!--more-->

[View the full advisory](/assets/advisories/20181108_WeBid_Multiple_Vulnerabilities.txt)

~~~
                          Telekom Security
                        security.telekom.com

     Advisory: WeBid - Directory Traversal (Arbitrary Image File Read),
               Blind SQL Injection and Reflected Cross Site Scripting
 Release Date: 2018-12-03
       Author: Nils Stünkel <nils.stuenkel@t-systems.com>
          CVE: CVE-2018-1000867, CVE-2018-1000868, CVE-2018-1000882

  Application: WeBid, up to version 1.2.2
         Risk: Medium
Vendor Status: Fix committed


Overview:

  From webidsupport.com:
  "WeBid provides open source auction software which has been used around
  the world and has been downloaded over 100,000 times. It will allow you to
  quickly set up your own auction site and get started straight away."

  Multiple vulnerabilities were identified version 1.2.2 of the WeBid auction
  system.
  A Directory Traversal vulnerability allows an unauthenticated, remote
  attacker to read any PNG, JPEG or BMP image files that are accessible to
  the server. In certain PHP configurations, this could also be used to issue
  arbitrary requests against a other systems over HTTP, HTTPS, FTP or other
  protocols, enabling unintended network boundary traversal.
  Blind SQL injections were found in five scripts related to the "Your Auctions"
  functionality. An authenticated attacker could use these vulnerabilities to
  read data from the database, like password hashes or other secrets.
  Two Cross Site Scripting (XSS) vulnerabilities were also found, one of them
  in the user login page.

  Fixes for all three vulnerabilities have been committed to the Github
  Repository on Nov 22nd, 2018 [7].


Details:

  1) Directory Traversal (Arbitrary Image File Read)
    In WeBid, the getthumb.php script handles the creation, caching and
    delivery of image thumbnails as they are requested by a client. However,
    no sanitization or boundary checking takes place on the 'fromfile' parameter
    value. An attacker can pass directory traversal tokens like '../' and have
    the application read and return arbitrary image files from the local file
    system. The vulnerability was reported to the project via their Mantis,
    the issue no. is 646[1].

    $fromfile = (isset($_GET['fromfile'])) ? $_GET['fromfile'] : '';
    $img = @getimagesize($fromfile);
    /* some more image format detection, setting $image_type and $output_type
    appropriately */
    load_image($fromfile, $img['mime'], $image_type, $output_type);
    /* load_image passes $fromfile to the corresponding imagecreatefrom*
    function and returns the resulting image to the client */

    If allow_url_include[2] is enabled in PHP, the attacker could use PHP
    protocol wrappers[3] to initiate outgoing connections from the web server,
    e.g. towards a protected network, and possibly exfiltrate data. There
    is currently no recommendation in the official WeBid documentation[4]
    to disable allow_url_include.
    When file types are requested that are not images, the vulnerability still
    allows the attacker to determine the presence of files on the system,
    as the error messages differ when the target file cannot be parsed
    ("Incorrect file type"), vs. when it doesn't exist ("Image not found").


  2) Multiple Authenticated Blind SQL Injection Vulnerabilities
    A number of scripts are passing unsanitized parameter values to the database,
    and can therefore be leveraged for blind SQL injection. A user has to be
    logged in for these vulnerabilities to be exploitable. This vulnerability
    was reported as issue no. 647[5].

    The following scripts and parameters are exploitable:

    Script                | Parameter
    ----------------------+------------
    yourauctions.php      | oa_ord
    yourauctions_c.php    | ca_ord
    yourauctions_p.php    | pa_ord
    yourauctions_s.php    | sa_ord
    yourauctions_sold.php | solda_ord


    // One possible code path copies the GET parameters into the session:
    $_SESSION['oa_ord'] = $_GET['oa_ord'];
    $_SESSION['oa_type'] = $_GET['oa_type'];

    // then the query is constructed
    $query = "SELECT * FROM " . $DBPrefix . "auctions
    WHERE user = :user_id AND closed = 0
    AND starts <= CURRENT_TIMESTAMP AND suspended = 0
    ORDER BY " . $_SESSION['oa_ord'] . " " . $_SESSION['oa_type'] . " LIMIT
    :offset, :perpage";

    // and executed
    $db->query($query, $params);


  3) Multiple Cross Site Scripting Vulnerabilities
    The scripts 'user_login.php' and 'register.php' were found to be vulnerable
    for Script Injection Attacks. When their respective action fails, their
    form fields are echoed back to client without any sanitization, allowing
    arbitrary JavaScript or Markup to be injected in the process. This
    vulnerability was reported as issue no. 648[6].
    
    From user_login.php:
    $template->assign_vars(array(
        'ERROR' => (isset($ERR)) ? $ERR : '',
        'USER' => (isset($_POST['username'])) ? $_POST['username'] : ''
        ));
        

References:

  [1]: http://bugs.webidsupport.com/view.php?id=646
  [2]: http://php.net/manual/en/features.remote-files.php
  [3]: http://php.net/manual/en/wrappers.php
  [4]: http://docs.webidsupport.com/build/html/installation.html
  [5]: http://bugs.webidsupport.com/view.php?id=647
  [6]: http://bugs.webidsupport.com/view.php?id=648
  [7]: https://github.com/renlok/WeBid/commit/256a5f9d3eafbc477dcf77c7682446cc4b449c7f


Disclosure Timeline:

  08. November   2018 - Directory Traversal Discovered
  09. November   2018 - SQL Injection and XSS Discovered
  09. November   2018 - Vendor Contact Requested
  12. November   2018 - Reported Issues to Vendor via their Mantis
  22. November   2018 - Fixes committed to Github[7]
  03. December   2018 - Advisory published


About Telekom Security:

  Telekom Security is the security provider for Deutsche Telekom and Deutsche
  Telekom customers.

  https://telekomsecurity.github.io
  https://security.telekom.com
  http://www.sicherheitstacho.eu
~~~
