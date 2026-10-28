# GitHub Pages deployment and rollback

The workflow builds pull requests and pushes and uploads `site-preview` for review. Deployment is disabled until the repository Actions variable `PAGES_DEPLOY_ENABLED` is set to `true`. The production site currently uses the legacy build from `master` at `/`. Preserve the Pages custom domain `github.security.telekom.com`, HTTPS enforcement, DNS, and the root `CNAME` throughout the migration.

## Before switching

1. Merge the reviewed workflow and dependency changes into `master`, leaving `PAGES_DEPLOY_ENABLED` unset. Confirm a successful build and download its `site-preview` artifact. Compare representative posts, pagination, sitemap, CSS, images, links and navigation with the live site. Review differences and obtain explicit approval.
2. Record the current master commit and Pages settings, the latest successful deployment, DNS, HTTPS enforcement, and certificate status. Save the last working site artifact and identify a person able to operate the repository. Record the migration commit and the last known good legacy-compatible commit; do not revert unrelated content.
3. Prepare a tested rollback change restoring the previous `Gemfile` and `Gemfile.lock` while retaining the root `CNAME`. The legacy build uses the vulnerable rubyzip dependency; its temporary use requires the agreed risk acceptance. GitHub's deployment and cache timing are outside our control, so the 15-minute target is not guaranteed. Assess any unproven rollback risk before approval.

## Switch and verify

1. In Settings > Pages, change the build source from branch `master`, `/` to GitHub Actions. Do not alter the custom domain or HTTPS enforcement.
2. Set the repository Actions variable `PAGES_DEPLOY_ENABLED` to `true` and manually run **Build and deploy Pages** on `master`. Verify both jobs succeed. Subsequent pushes to `master` deploy automatically.
3. Check the Pages settings and certificate, `http://telekom-security.github.io/` redirect, `https://github.security.telekom.com/`, representative content, assets, pagination and sitemap. Repeat checks during 30 minutes of observation. Account for GitHub's caches and verify the deployed content, not only HTTP status.

## Rollback

1. Set `PAGES_DEPLOY_ENABLED` to `false` and cancel any running or queued deployment workflows. Confirm no deployment remains in progress.
2. Restore the prior legacy-compatible `Gemfile` and `Gemfile.lock` on `master` using the prepared rollback change; preserve subsequent content and the root `CNAME`. Merge using the repository's normal protections.
3. Change Settings > Pages back to **Deploy from a branch**, `master`, `/ (root)`. Verify the custom domain and HTTPS enforcement are still correct. Trigger a legacy build if necessary and monitor its completion.
4. Check both addresses, TLS, redirects and representative pages. Record completion time and any cache delay. If restoration exceeds the target or fails, escalate to the responsible operator; do not assume changing the setting alone has restored the site.
