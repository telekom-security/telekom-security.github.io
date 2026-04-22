# Contributing a Blog Post

## Front Matter Reference

Every post lives in the `_posts/` directory as a Markdown file named `YYYY-MM-DD-slug.md`.
The YAML front matter block at the top controls metadata and SEO tags.

### Required Parameters

| Parameter     | Description                                      | Example                                      |
|---------------|--------------------------------------------------|----------------------------------------------|
| `title`       | Post title (used in `<title>` and as fallback for OG/Twitter titles) | `Shining some light on the DarkGate loader` |
| `header`      | Displayed heading on the post page               | `Shining some light on the DarkGate loader`  |
| `tags`        | List of tags for categorisation                  | `['advisories']`, `['research']`, `['writeup']` |

### Recommended Parameters

| Parameter     | Description                                      | Example                                      |
|---------------|--------------------------------------------------|----------------------------------------------|
| `description` | Short summary (50–160 chars). Used for `<meta name="description">` and as fallback for OG/Twitter descriptions. If omitted, the post excerpt is used. | `Discovery of printer CVE during Red Team assessment` |
| `author`      | Author name                                      | `msatdt`                                     |
| `date`        | Publication date (overrides the filename date)   | `2026-02-26`                                 |
| `image`       | Post-specific image path (relative to site root). Used as fallback for `og:image` / `twitter:image`. Defaults to `/img/favicon.png`. | `/img/posts/darkgate-banner.png` |

### Optional OG / Social Media Overrides

These parameters let you override the auto-generated Open Graph and Twitter Card values.
If omitted, the template falls back to the standard parameters listed above.

| Parameter          | Overrides              | Fallback                                | Example                                      |
|--------------------|------------------------|-----------------------------------------|----------------------------------------------|
| `og_title`         | `og:title`, `twitter:title` | `title` → `site.title`            | `DarkGate Loader Deep-Dive`                  |
| `og_description`   | `og:description`, `twitter:description` | `description` → post excerpt → `site.description` | `A technical analysis of the DarkGate loader infection chain` |
| `og_image`         | `og:image`, `twitter:image` | `image` → `/img/favicon.png`       | `/img/posts/darkgate-social.png`             |

> **Article preview image:** When `og_image` is set to something other than the
> default favicon, it is also displayed as a visual preview:
> - **Index page** – the image is shown as a 16:9 thumbnail floated to the left
>   of the post excerpt.
> - **Article page** – the image is shown floated to the left at the start of
>   the article content. Clicking any image in an article opens it in a
>   full-screen modal overlay; clicking anywhere outside the image closes the
>   modal.

| `og_type`          | `og:type`              | `article` (posts) / `website` (pages)   | `profile`                                    |
| `twitter_card`     | `twitter:card`         | `summary`                               | `summary_large_image`                        |
| `twitter_creator`  | `twitter:creator`      | *(not set)*                             | `@marqufabi`                                 |

### Advisory-Specific Parameters

Posts tagged `advisories` commonly include extra metadata:

| Parameter                    | Description                          | Example                                      |
|------------------------------|--------------------------------------|----------------------------------------------|
| `cwes`                       | List of CWE identifiers              | `['CWE-79', 'CWE-922']`                     |
| `affected_product`           | Name of the affected product         | `Airmail - Your Mail With You`               |
| `vulnerability_release_date` | Date the vulnerability was published | `2024-03-14`                                 |

## Minimal Example

```yaml
---
title: My New Security Advisory
header: My New Security Advisory
description: A brief summary of the advisory for search engines and social previews.
author: jdoe
date: 2026-03-06
tags: ['advisories']
---
```

## Full Example (with OG overrides)

```yaml
---
title: My New Security Advisory
header: My New Security Advisory
description: A brief summary of the advisory for search engines and social previews.
author: jdoe
date: 2026-03-06
tags: ['advisories']
image: /img/posts/advisory-banner.png
og_title: "Advisory: Critical Flaw in WidgetCorp"
og_description: "We discovered a critical vulnerability in WidgetCorp affecting versions < 3.2."
og_image: /img/posts/advisory-social.png
twitter_card: summary_large_image
twitter_creator: "@jdoe_sec"
cwes: ['CWE-89']
affected_product: 'WidgetCorp Server'
vulnerability_release_date: '2026-02-15'
---

Post body starts here. Use `<!--more-->` to mark the excerpt break.
```

## Fallback Chain

The template resolves OG and Twitter meta tags in this order:

```
og:title       ← og_title       → title        → site.title
og:description ← og_description → description  → excerpt → site.description
og:image       ← og_image       → image        → /img/favicon.png
og:type        ← og_type        → "article" (if post) / "website" (if page)
twitter:card   ← twitter_card   → "summary"
twitter:creator← twitter_creator→ (omitted if not set)
```
