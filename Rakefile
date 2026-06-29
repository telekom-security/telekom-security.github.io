require "date"
require "English"
require "fileutils"
require "open3"
require "set"
require "uri"
require "yaml"

POSTS_DIR = "_posts"
ASSET_DIRS = ["assets", "img"].freeze
POST_FILE_RE = /\A\d{4}-\d{2}-\d{2}-.+\.md\z/
RAW_CODE_ALLOWLIST = Set.new.freeze

def post_files
  Dir.glob("#{POSTS_DIR}/**/*.md").sort
end

def slugify(value)
  value
    .downcase
    .gsub(/&/, " and ")
    .gsub(/[^a-z0-9]+/, "-")
    .gsub(/\A-+|-+\z/, "")
    .gsub(/-{2,}/, "-")
end

def parse_tags(value)
  value.to_s.split(",").map(&:strip).reject(&:empty?)
end

def read_frontmatter(source)
  normalized = source.gsub("\r\n", "\n")
  return nil unless normalized.start_with?("---\n")

  end_index = normalized.index("\n---", 4)
  return nil unless end_index

  normalized[4...end_index]
end

def frontmatter_hash(frontmatter)
  YAML.safe_load(frontmatter, permitted_classes: [Date, Time], aliases: true) || {}
rescue Psych::SyntaxError
  nil
end

def strip_fenced_code(source)
  source.gsub(/```[\s\S]*?```/, "")
end

def raw_script_or_style?(source)
  strip_fenced_code(source).lines.any? { |line| line.match?(/\A\s{0,3}<(script|style)\b/i) }
end

def local_asset_paths(source)
  patterns = [
    /!\[[^\]]*\]\((\/(?:assets|img)\/[^)\n]+)\)/,
    /\b(?:src|href)=["'](\/(?:assets|img)\/[^"']+)["']/,
    /^(?:image|og_image):\s*['"]?(\/(?:assets|img)\/[^'"\n]+)['"]?/,
  ]

  patterns.flat_map { |pattern| source.scan(pattern).flatten }
          .map { |path| URI.decode_www_form_component(path.strip.sub(/\s+["'][^"']+["']\z/, "")) }
          .uniq
end

desc "Create a publish-ready post: bundle exec rake new_post title=\"...\" tags=\"research\" description=\"...\""
task :new_post do
  title = ENV["title"] || ENV["TITLE"]
  tags = parse_tags(ENV["tags"] || ENV["TAGS"])
  description = ENV["description"] || ENV["DESCRIPTION"]
  author = ENV["author"] || ENV["AUTHOR"]
  date = ENV["date"] || ENV["DATE"] || Date.today.strftime("%Y-%m-%d")
  slug = slugify(ENV["slug"] || ENV["SLUG"] || title.to_s)
  draft = ENV["draft"] == "true" || ENV["DRAFT"] == "true"

  abort "Missing title=\"...\"" if title.to_s.strip.empty?
  abort "Missing tags=\"...\"" if tags.empty?
  abort "Missing description=\"...\"" if description.to_s.strip.empty?
  abort "Date must be YYYY-MM-DD" unless date.match?(/\A\d{4}-\d{2}-\d{2}\z/)
  abort "Slug is empty after normalization; pass slug=\"...\"" if slug.empty?

  Date.iso8601(date)
  FileUtils.mkdir_p(POSTS_DIR)
  path = File.join(POSTS_DIR, "#{date}-#{slug}.md")
  abort "Post already exists: #{path}" if File.exist?(path)

  frontmatter = [
    "---",
    "title: '#{title.gsub("'", "''")}'",
    "header: '#{title.gsub("'", "''")}'",
    "description: '#{description.gsub("'", "''")}'",
    (author ? "author: '#{author.gsub("'", "''")}'" : nil),
    "tags: [#{tags.map { |tag| "'#{tag.gsub("'", "''")}'" }.join(", ")}]",
    (draft ? "draft: true" : nil),
    "---"
  ].compact.join("\n")

  File.write(path, <<~POST)
    #{frontmatter}

    Write the opening paragraph here. Keep it specific enough to work as the listing excerpt.

    <!--more-->

    Continue the article here.

    ## Assets

    Place local images and downloads under `assets/` and reference them with root-relative paths, for example `/assets/images/example.png`.
  POST

  year, month, = date.split("-")
  puts "Created #{path}"
  puts "Public URL: /#{year}/#{month}/#{slug}.html"
  puts "Draft mode: visible with demo config only." if draft
end

desc "Validate posts, frontmatter, raw script/style policy, and local assets"
task :check_content do
  errors = []

  post_files.each do |path|
    filename = File.basename(path)
    source = File.read(path)
    frontmatter = read_frontmatter(source)

    errors << "#{path}: filename must be YYYY-MM-DD-slug.md" unless filename.match?(POST_FILE_RE)

    unless frontmatter
      errors << "#{path}: missing YAML frontmatter"
      next
    end

    data = frontmatter_hash(frontmatter)
    unless data
      errors << "#{path}: invalid YAML frontmatter"
      next
    end

    %w[title header].each do |key|
      errors << "#{path}: missing required frontmatter key '#{key}'" if data[key].to_s.strip.empty?
    end

    tags = data["tags"]
    errors << "#{path}: missing non-empty 'tags' frontmatter" unless tags.respond_to?(:any?) && tags.any?

    if raw_script_or_style?(source) && !RAW_CODE_ALLOWLIST.include?(path)
      errors << "#{path}: raw <script> or <style> is not allowed in posts"
    end

    local_asset_paths("#{frontmatter}\n#{source}").each do |asset|
      file_path = asset.sub(%r{\A/}, "")
      errors << "#{path}: referenced asset not found: #{asset}" unless File.exist?(file_path)
    end
  end

  if errors.any?
    warn "Content check failed:"
    errors.each { |error| warn "- #{error}" }
    exit 1
  end

  puts "Content check OK (#{post_files.length} posts)."
end

desc "Report conservative content cleanup candidates without failing"
task :audit_content do
  missing_excerpt = []
  raw_html = []
  http_links = []
  jekyll_patterns = []
  referenced_assets = Set.new

  post_files.each do |path|
    source = File.read(path)
    missing_excerpt << path unless source.include?("<!--more-->")
    raw_html << path if raw_script_or_style?(source)
    http_links << path if source.match?(%r{http://})
    jekyll_patterns << path if source.match?(/\{\%|\{\{/) || source.match?(/\{:\s*\./)
    local_asset_paths(source).each { |asset| referenced_assets << asset.sub(%r{\A/}, "") }
  end

  assets = ASSET_DIRS.flat_map { |dir| Dir.glob("#{dir}/**/*").select { |entry| File.file?(entry) } }
  unreferenced = assets.reject { |asset| referenced_assets.include?(asset) }

  {
    "Posts without <!--more--> excerpt marker" => missing_excerpt,
    "Posts containing raw <script> or <style>" => raw_html,
    "Posts containing http:// links" => http_links,
    "Posts containing possible Jekyll/Liquid patterns" => jekyll_patterns,
    "Potentially unreferenced public assets" => unreferenced
  }.each do |title, entries|
    next if entries.empty?

    puts "\n#{title} (#{entries.length})"
    entries.each { |entry| puts "- #{entry}" }
  end

  puts "\nContent audit completed. This report is informational and does not fail CI."
end

desc "Run bundler-audit"
task :security_audit do
  system("bundle", "exec", "bundle-audit", "check", "--update") || exit($CHILD_STATUS.exitstatus || 1)
end

desc "Run the local CI gate"
task ci: [:check_content, :audit_content, :security_audit] do
  system("bundle", "exec", "jekyll", "build") || exit($CHILD_STATUS.exitstatus || 1)
end
