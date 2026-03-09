# telekom-security.github.io :globe_with_meridians:

This is the jekyll source for our blog. You can browse it on https://telekom-security.github.io.


## Development Usage

### Local (Ruby required)

1. `gem install bundler`
2. `bundle install`
3. `bundle exec jekyll serve`

### Container (podman / docker)

A `Containerfile.dev` is provided for local development **without** installing
Ruby on the host. The repository is bind-mounted into the container so that
every file change is picked up immediately by Jekyll's `--incremental` rebuild.

#### 1. Build the dev image (one-time)

```bash
podman build -f Containerfile.dev -t telekom-blog-dev .
```

#### 2. Run with a bind-mount

```bash
podman run --rm -it \
  -v "$(pwd)":/site:Z \
  -p 4000:4000 \
  telekom-blog-dev
```

| Flag | Purpose |
|---|---|
| `-v "$(pwd)":/site:Z` | Mounts the repo into `/site` inside the container. The `:Z` suffix adjusts SELinux labels (required on Fedora / RHEL; omit on other distros). |
| `-p 4000:4000` | Forwards the Jekyll dev server port. |
| `--rm` | Removes the container when it stops. |

Open <http://localhost:4000> in your browser.
Jekyll watches for file changes and rebuilds automatically; livereload will
refresh the page in your browser.

#### Replacing the Gemfile

If you change `Gemfile`, rebuild the image so the new gems are installed into
the cached layer:

```bash
podman build --no-cache -f Containerfile.dev -t telekom-blog-dev .
```
