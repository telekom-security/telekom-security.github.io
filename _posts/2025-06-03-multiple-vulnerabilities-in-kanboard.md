---
title: Multiple vulnerabilities in Kanboard (Exploiting web applications Part II)
header: Multiple vulnerabilities in Kanboard (Exploiting web applications Part II)
tags: ['advisories', 'writeup']
cwes: ['Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) (CWE-22)']
affected_product: 'Kanboard'
vulnerability_release_date: '2024-11-11'
---

This article is a continuation of a write-up series, where we discuss web application vulnerabilities found during red team operations. This time, the target was the Kanboard software. <!--more-->

### Project Management in Kanboard style

With over 8000 stars on GitHub, [Kanboard](https://github.com/kanboard/kanboard) is one of the most popular applications for organizing projects following the Kanban approach.

During one of our red team assessments, we discovered that our client self-hosts an instance of Kanboard.
Since it is open-source, we decided to hunt for vulnerabilities by reading the source code and penetration testing in parallel. 

So, it all started with a `git clone`. We used the `ack` tool as an in place grep replacement, which helped us find interesting code sections. Browsing through the code leaves the first impression that it is well structured and cleanly written.


#### Initial access and juicy features

But first, let's switch to the customer instance again - not having said yet that the good old `admin:admin` credential set helped us out once again :)
We could successfully authenticate as the administrator and thus open us various possibilities to potentially exploit application functionalities.

Having administrative access to the Kanboard instance also gives us lots of interesting information about the target's project details including network and system configurations. But can we abuse the server?
We browse through different projects, boards, comments, item details and uploaded attachments.

![Download Database](/assets/images/kanboard/download-database.png)

One interesting feature of Kanboard is allowing administrators to download the complete SQLite database as a gzip file or upload it to update the database.
So we did this: a surprise backup of our target instance.
We decompress the downloaded file by executing `gzip -d db.sqlite.gz` and open it with an SQLite browser.

We can see the raw data of projects, comments, etc.
Especially the `project_has_files` table holds our attention, as it stores relative file paths of uploaded files.
So we switched to the source code repository and looked through the source code, to determine how the the filepaths are read and used within the application.

##### Write and delete files - but what about reading them?

In the web UI, we see that uploaded files can be downloaded through URLs like this: `https://example.com/project/1/file/1/download/<hash>`.
So searching through the code base for `/download` points us to the underlying PHP class that is responsible for serving files: the [FileViewerController](https://github.com/kanboard/kanboard/blob/v1.2.41/app/Controller/FileViewerController.php).

```bash
$ ack "/download"
ServiceProvider/RouteProvider.php
77:  $container['route']->addRoute('project/:project_id/file/:file_id/download/:etag', 'FileViewerController', 'download');
148: $container['route']->addRoute('task/:task_id/file/:file_id/download/:etag', 'FileViewerController', 'download');
```

The below `download()` function of the [FileViewerController.php](https://github.com/kanboard/kanboard/blob/v1.2.41/app/Controller/FileViewerController.php#L152) looks very simple. But what exactly do `$this->getFile();` and `$this->objectStorage->output($file['path']);` do?

```php
public function download()
{
    try {
        $file = $this->getFile();
        $this->response->withFileDownload($file['name']);
        $this->response->send();
        $this->objectStorage->output($file['path']);
    } catch (ObjectStorageException $e) {
        $this->logger->error($e->getMessage());
    }
}
```
`$this->getFile()` is a call to the super class of [BaseController](https://github.com/kanboard/kanboard/blob/v1.2.41/app/Controller/BaseController.php#L93). 

```php
protected function getFile()
{
    $project_id = $this->request->getIntegerParam('project_id');
    $task_id = $this->request->getIntegerParam('task_id');
    $file_id = $this->request->getIntegerParam('file_id');
    
    [...]
}
```

We see that this function parses the `project_id` and `file_id` parameter values that we already saw in the route definition of download URLs. The function essentially parses the two values from the URL, performs a SQL select on the attachments and returns an array with the data, collected from the SQL entry. No path sanitization that we can see so far!

So lets check the `output()` function of the objectStorage, which is defined in [FileStorage.php](https://github.com/kanboard/kanboard/blob/v1.2.41/app/Core/ObjectStorage/FileStorage.php#L75). 

```php
public function output($key)
{
    $filename = $this->path.DIRECTORY_SEPARATOR.$key;

    if (! file_exists($filename)) {
        throw new ObjectStorageException('File not found: '.$filename);
    }

    readfile($filename);
}
```

The function retrieves the `$key` parameter, which in this case is a relative path from the SQLite database, checks the file's existence and returns its content. No checks - this smells like a arbitrary file read if we are able to modify the path successfully.

Since we are certain that the application is vulnerable to an arbitrary file read, we immediately test it out:

1. We download the database 
2. Decompress it via `gzip -d db.sqlite.gz`
3. Open it in a SQL browser and go to table `project_has_files`.
4. For one of the already uploaded files, we modify the `path` to something we want to read `../../../../../../../etc/passwd`
5. Commit our SQL changes and save the file
6. Compress it again with `gzip db.sqlite`
7. Upload it to the server 
8. Download the modified file via the web ui

And what we get is:

![/etc/passwd](/assets/images/kanboard/passwd.png)

Hurray! We are able to read arbitrary files from the server - further a "referenced" file can be deleted (if Kanboard has sufficient permissions) via the web ui.
This vulnerability has been assigned CVE-2024-51747 - reported via [GHSA-78pf-vg56-5p8v](https://github.com/kanboard/kanboard/security/advisories/GHSA-78pf-vg56-5p8v).

##### code `exec` 

File reads are nice - but we prefer to have code execution on the target. So we still decided to look deeper.
When reviewing PHP code it's always a good start to check for the known dangerous php functions assembled [in this great collection](https://gist.github.com/mccabe615/b0907514d34b2de088c4996933ea1720).

```bash
$ ack -i "system\s*\(" --php
ServiceProvider/LoggingProvider.php
42:  $driver = new System();
$ ack -i "shell_exec\s*\(" --php
```

Unfortunately, we have no results except false positives in our source code, when we grepped for command execution functions.

However, one result with a `require` statement looks interesting.

```bash
$ ack -i "require\s*\(" --php
app/Core/Translator.php
176:            self::$locales = array_merge(self::$locales, require($filename));
```

`require` is a PHP language statement to include other files, which leads directly to RCE, if the file is controllable.
Having a `$filename` variable - that could be controllable by us - looks interesting.
Let's see where `$filename` comes from and which value it has.
It is defined in [Translator.php](https://github.com/kanboard/kanboard/blob/v1.2.41/app/Core/Translator.php#L173) in the load() function.

```php
public static function load($language, $path = '')
{
    if ($path === '') {
        $path = self::getDefaultFolder();
    }

    $filename = implode(DIRECTORY_SEPARATOR, array($path, $language, 'translations.php'));

    if (file_exists($filename)) {
        self::$locales = array_merge(self::$locales, require($filename));
    }
}
```

The `load()` function seems to be called from [LanguageModel.php](https://github.com/kanboard/kanboard/blob/v1.2.41/app/Model/LanguageModel.php#L214).

```bash
$ ack -i "load\s*\(" --php
Model/LanguageModel.php
214:    Translator::load($this->getCurrentLanguage());
```

And it depends on `getCurrentLanguage()` from the same class.

```php
public function getCurrentLanguage()
{
    return $this->userSession->getLanguage() ?: $this->configModel->get('application_language', 'en_US');
}

/**
 * Load translations for the current language
 *
 * @access public
 */
public function loadCurrentLanguage()
{
    Translator::load($this->getCurrentLanguage());
}
```

Do you spot something fishy? Maybe not, since we haven't explained it yet - but `$this->configModel->get('application_language', 'en_US');` reads a configuration value from the SQLite `settings` table. In particular, it reads the `application_language` entry or defaults to `en_US`.
Since we already inspected all further handling of the the `application_language`  value we can conclude that this fields leads to a constrained RCE on the server!

If we set `application_language` to an arbitrary path via path traversal, the value will be used to construct the `$filename` path, which we saw before. 
However, at the end of the path, the code adds a `translations.php`. Meaning, if we are able to write a `translations.php` file anywhere on the server, where Kanboard can read it and modify the SQLite database accordingly, then we achieve code execution because Kanboard includes this file.

We tried to abuse this, by uploading a `translations.php` file via Kanboard's file attachments function, but the files are not saved with their original filename, but with a hash instead. This leaves us unlucky to abuse it all-at-once :S


This vulnerability has been assigned CVE-2024-51748 - reported via [GHSA-jvff-x577-j95p](https://github.com/kanboard/kanboard/security/advisories/GHSA-jvff-x577-j95p).


Last but not least, after reporting all vulnerabilities we noticed on retesting that we are still logged in in our testing instance after multiple days. How can this be?

It turns out that the session invalidation was not working properly, thus keeping sessions alive for an indefinite time.
This vulnerability has been assigned CVE-2024-55603 - reported via [GHSA-gv5c-8pxr-p484](https://github.com/kanboard/kanboard/security/advisories/GHSA-gv5c-8pxr-p484) with additional details.

These findings once again show the danger of default credentials, giving initial access, which than can be used to exploit a system.
Also it shows, that even configuration data cannot be trusted - user controllable input must be properly sanitized in all cases.


-----

Timeline:

* **2024-10-31:** Vulnerability [CVE-2024-51747](https://github.com/kanboard/kanboard/security/advisories/GHSA-78pf-vg56-5p8v) and [CVE-2024-51748](https://github.com/kanboard/kanboard/security/advisories/GHSA-jvff-x577-j95p) has been reported to the vendor.
* **2024-11-03:** Vendor has reported that the vulnerabilities will be fixed in next release.
* **2024-11-10:** Kanboard 1.2.42 has been released with both fixes.
* **2024-11-18:** Vulnerability [CVE-2024-55603](https://github.com/kanboard/kanboard/security/advisories/GHSA-gv5c-8pxr-p484) has been reported to the vendor.
* **2024-12-08:** Vendor has reported that the vulnerability will be fixed in next release.
* **2024-12-18:** Kanboard 1.2.43 has been released with the fix.
* **2025-05-08:** This blog post was published.

<style>
img {
  border: 1px solid #555;
}
</style>
