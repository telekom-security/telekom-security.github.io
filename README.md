# telekom-security.github.io

Jekyll source for the Telekom Security research and publications site.

Production domain: <https://github.security.telekom.com>

## TL;DR: Publish a Post

```bash
rbenv install -s 3.3.4
rbenv local 3.3.4
ruby -v
bundle install
bundle exec rake new_post title="My Title" tags="research" description="Short summary"
bundle exec jekyll serve --livereload
bundle exec rake ci
git add .
git commit -m "Add post: My Title"
git push origin master
```

After the push, check the GitHub Pages `pages-build-deployment` run. A
successful run deploys the site to GitHub Pages.

## Requirements

- Ruby 3.3.4, matching `.ruby-version` and the current GitHub Pages runtime.
- Bundler with `Gemfile.lock`; Ruby 3.3.4 usually ships with Bundler, so use
  `bundle install` for a clean local install.
- GitHub Pages remains configured as the legacy branch build from `master /`.
- No deploy workflow is required for this Jekyll setup.

## Install the Development Environment

### macOS

Install Apple's command line tools if `git` is missing:

```bash
xcode-select --install
```

Install Ruby with Homebrew and rbenv:

```bash
brew install rbenv ruby-build
```

Enable rbenv in your shell. macOS uses zsh by default:

```bash
echo 'eval "$(rbenv init - zsh)"' >> ~/.zshrc
exec zsh -l
```

If you use bash instead:

```bash
echo 'eval "$(rbenv init - bash)"' >> ~/.bashrc
exec bash -l
```

Install and activate Ruby:

```bash
rbenv install -s 3.3.4
rbenv local 3.3.4
ruby -v
which ruby
gem env home
bundle -v || gem install bundler
bundle install
```

`ruby -v` must print `ruby 3.3.4...`, `which ruby` must point to an rbenv
shim, and `gem env home` must not point to `/Library/Ruby/Gems/...`.

### Linux

Debian/Ubuntu prerequisites:

```bash
sudo apt update
sudo apt install -y git curl build-essential libssl-dev libreadline-dev zlib1g-dev
```

Install rbenv:

```bash
curl -fsSL https://github.com/rbenv/rbenv-installer/raw/main/bin/rbenv-installer | bash
```

Add rbenv to your shell profile:

```bash
export PATH="$HOME/.rbenv/bin:$PATH"
eval "$(rbenv init - bash)"
```

For bash, persist that setup with:

```bash
echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(rbenv init - bash)"' >> ~/.bashrc
exec bash -l
```

For zsh, use `~/.zshrc` and `rbenv init - zsh` instead.

Install and activate Ruby:

```bash
rbenv install -s 3.3.4
rbenv local 3.3.4
ruby -v
which ruby
gem env home
bundle -v || gem install bundler
bundle install
```

`ruby -v` must print `ruby 3.3.4...`, `which ruby` must point to an rbenv
shim, and `gem env home` must not point to a system Ruby directory.

## Local Development

Normal local server:

```bash
bundle exec jekyll serve --livereload
```

Open <http://localhost:4000>.

Demo mode includes draft and future posts and emits `noindex` metadata:

```bash
bundle exec jekyll serve --livereload --config _config.yml,_config_demo.yml
```

Containerized demo mode:

```bash
docker compose up demo
```

## Checks

Run the full local gate before publishing:

```bash
bundle exec rake ci
```

Individual checks:

```bash
bundle exec rake check_content
bundle exec rake audit_content
bundle exec rake security_audit
bundle exec jekyll build
```

`check_content` is blocking. It validates post filenames, required frontmatter,
local asset references, and disallows new raw `<script>` or `<style>` blocks in
posts.

`audit_content` is informational. It reports legacy patterns such as missing
excerpt markers, HTTP links, raw HTML in historical posts, possible Jekyll
patterns, and potentially unreferenced assets. Do not delete historical assets
solely based on this report; old posts or external deep links may still use
them.

`security_audit` runs `bundler-audit` against the current bundle.

## Create a New Post

Use the generator:

```bash
bundle exec rake new_post title="My Title" tags="ThreatIntel" description="Short summary"
```

Optional parameters:

```bash
author="Name"
date="YYYY-MM-DD"
slug="custom-slug"
draft="true"
```

The default is publish-ready. The script does not add `draft: true` unless
`draft="true"` is passed. Publishing still requires manual `git commit` and
`git push`.

Posts live in `_posts/` and keep the historical filename format:

```text
YYYY-MM-DD-slug.md
```

The filename defines the public URL:

```text
/YYYY/MM/slug.html
```

Use `<!--more-->` after the opening paragraph. Everything before this marker is
used as the listing excerpt.

## Frontmatter Reference

Required:

| Field | Description | Example |
|---|---|---|
| `title` | SEO fallback title | `Shining some light on the DarkGate loader` |
| `header` | Displayed article headline | `Shining some light on the DarkGate loader` |
| `tags` | Category/tag list | `['advisories']`, `['ThreatIntel']` |

Recommended:

| Field | Description | Example |
|---|---|---|
| `description` | Meta description; excerpt is fallback | `Discovery of printer CVE during Red Team assessment` |
| `author` | Author name | `jdoe` |
| `image` | Listing/article image path | `/assets/images/example.png` |

Optional social overrides:

| Field | Used for | Fallback |
|---|---|---|
| `og_title` | `og:title`, `twitter:title` | `header` or `title` |
| `og_description` | `og:description`, `twitter:description` | `description` or excerpt |
| `og_image` | `og:image`, `twitter:image`, preview image | `image` or default site image |
| `og_type` | `og:type` | `article` for posts |
| `twitter_card` | `twitter:card` | `summary` |
| `twitter_creator` | `twitter:creator` | omitted |

Advisory-specific fields for `/advisories.html`:

| Field | Description | Example |
|---|---|---|
| `cwes` | CWE list | `['CWE-79', 'CWE-922']` |
| `affected_product` | Affected product | `Airmail - Your Mail With You` |
| `vulnerability_release_date` | Advisory publication date | `2026-02-15` |

## Tags and Categories

Primary category labels are derived from the first matching tag:

| Tag | Display label |
|---|---|
| `ThreatIntel` | `Threat Intelligence` |
| `advisories` | `Security Advisory` |
| `Honeypots` | `Honeypot Research` |
| `tools` | `Tooling` |
| `research` | `Research Note` |
| `writeup` or `Write-up` | `Write-up` |
| `general` or `General` | `General Update` |

Use the established tag names above for new posts unless a new category is
intentionally introduced in `_data/categories.yml`.

## Assets

Static files live in the repository root and are served from the site root.

Examples:

| File | Public URL |
|---|---|
| `assets/images/example.png` | `/assets/images/example.png` |
| `assets/advisories/report.pdf` | `/assets/advisories/report.pdf` |
| `img/favicon.png` | `/img/favicon.png` |

Rules for new posts:

- Prefer local assets under `assets/...`.
- Use root-relative paths, for example `/assets/images/example.png`.
- Avoid spaces in new filenames. Historical assets with spaces remain supported.
- Do not add inline `<script>` or `<style>` to Markdown posts.
- Use existing global classes such as `img-small` instead of per-post CSS.

## Publish Flow

1. Create the post with `bundle exec rake new_post`.
2. Add images or downloads under `assets/...`.
3. Run `bundle exec jekyll serve --livereload` for normal local testing.
4. Run demo mode only when checking draft or future posts.
5. Run `bundle exec rake ci`.
6. Review `git diff`.
7. Commit manually.
8. Push to `master`.
9. Check the GitHub Pages `pages-build-deployment` run.

GitHub Pages builds from `master /` with its native Jekyll pipeline. The site
does not require a custom deploy workflow.

## Troubleshooting

- If Ruby version errors appear, verify `ruby -v` prints `3.3.4`.
- If `ruby -v` still prints the macOS system Ruby, for example `2.6.x`, rbenv
  is not active in the current shell. Run `eval "$(rbenv init - zsh)"` once for
  the current terminal, then check `which ruby` again. Persist the setup in
  `~/.zshrc` as shown above.
- If `gem install bundler` tries to write to `/Library/Ruby/Gems/2.6.0`, stop
  before using `sudo`. That path belongs to macOS system Ruby. Fix rbenv first;
  after that `gem env home` should point below `~/.rbenv/versions/3.3.4/...`.
- If dependencies look inconsistent, run `bundle install`.
- If an asset is reported missing, verify the file exists under `assets/` or
  `img/` and the Markdown path starts with `/assets/` or `/img/`.
- If a post is not in production, check for `draft: true` or a future filename
  date.
- If GitHub Pages does not update after push, inspect the `pages-build-deployment`
  run and verify the Pages API still reports `build_type: legacy`.
