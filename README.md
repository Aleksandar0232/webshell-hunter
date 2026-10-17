# webshell-hunter

Bash scanner that finds PHP webshells, backdoors and injected JavaScript on a web server and moves them out of the webroot — reversibly.

Built for shared-hosting cleanup work (cPanel/WHM, CWP), but it runs on any Linux box with GNU `grep`/`find`.

## Why quarantine instead of delete

Deleting a hit destroys the sample you need for the ticket and gives you nothing to recover if the hit was a false positive (plugins use `base64_decode` and `eval` more often than you'd think). So the default is **report only**; `--quarantine` moves files to `/root/quarantine/<timestamp>/` with a manifest (sha256, owner, perms, original path) and `--restore` puts them back in one command.

## Usage

```bash
chmod +x webshell-hunter.sh

./webshell-hunter.sh                                   # report only, all /home/*/public_html
./webshell-hunter.sh -p /home/user/public_html         # one account
./webshell-hunter.sh -p /home/user/public_html --wp    # + WordPress checks (needs wp-cli)

./webshell-hunter.sh -p ... --quarantine               # move HIGH hits out (asks y/N)
./webshell-hunter.sh -p ... --quarantine --all         # MEDIUM hits too — review them first
./webshell-hunter.sh -p ... --delete --yes             # irreversible; you've been warned

./webshell-hunter.sh --restore /root/quarantine/<ts>/MANIFEST.txt
```

| Option | Meaning |
|---|---|
| `-p PATH` | path to scan (repeatable). Default: `/home/*/public_html`, `/var/www`, … |
| `-d DAYS` | list PHP/JS files modified in the last N days (default 7) |
| `-x REGEX` | exclude paths matching this pattern (repeatable) |
| `-o FILE` | report file (default `/root/webshell-report-<ts>.txt`) |
| `--quarantine` | move HIGH hits to `/root/quarantine/<ts>/` |
| `--all` | also act on MEDIUM hits |
| `--delete --yes` | delete instead of quarantining |
| `--wp` | run wp-cli checksum verification, list admins, scan the DB for injections |
| `--no-js` | skip the JavaScript scan |
| `--restore FILE` | undo a quarantine from its manifest |

Run as root.

## What it finds

**PHP — HIGH** (acted on by `--quarantine`)
- `eval(base64_decode(...))`, `eval(gzinflate(...))`, `eval(str_rot13(...))` and friends
- `system` / `exec` / `assert` / `passthru` fed from `$_GET` / `$_POST` / `$_COOKIE`
- `$_POST['a']($_POST['b'])`, `$f="system"; $f($_GET[...])`, `preg_replace` with `/e`
- known shell families: WSO, FilesMan, c99, r57, b374k, alfa, AnonymousFox, IndoXploit, p0wny, Gel4y …
- PHP with exec functions hidden inside `.gif` / `.ico` / `.css` / `.txt` / `.svg`
- `.htaccess` mapping the PHP handler to image extensions, `auto_prepend_file`, SEO-cloaking rewrites
- `.user.ini` / `php.ini` with `auto_prepend_file` / `auto_append_file`

**PHP — MEDIUM** (reported; acted on only with `--all`)
- obfuscation: `gzinflate(base64_decode(`, long hex / `chr()` strings, `$GLOBALS['x'][12]`-style indexing, `goto` spaghetti
- PHP files inside `uploads/`, `cache/`, `tmp/`, `backup/` …
- suspicious filenames (`wp-conf.php`, `about.php`, `class-wp-xyz12345.php`, `wso1.php`, `adminer.php` …)
- code that creates WordPress users or forges auth cookies

**JavaScript — HIGH**
- `eval(atob(...))`, `new Function(unescape(...))`, `document.write(unescape(...))`
- encoded `location.href =` redirects
- hidden iframes (0×0, `display:none`, offscreen)
- cryptominers (CoinHive, cryptonight, jsecoin, …)
- cookie exfiltration (`new Image().src = ... + document.cookie`)
- card skimmers (card/cvv fields → `btoa` → `fetch` / `sendBeacon`)
- hex- or unicode-escaped `eval` / `atob` (`\x65\x76\x61\x6c`), long `String.fromCharCode` chains feeding `eval`

**JavaScript — MEDIUM**
- `_0x…` obfuscator output that executes, dynamically built `<script src>`
- scripts loaded from throwaway TLDs (`.tw`, `.xyz`, `.top`, `.icu`, `.sbs`, …)
- user-agent / referrer-cloaked redirects
- `.js` files inside `uploads/`
- **mass injection**: the same suspicious snippet prepended or appended to 5+ `.js` files in the account (Balada / SocGholish style). Build-tool headers and footers (webpack, UMD wrappers, `sourceMappingURL`, license banners) are ignored.

The JS signatures also run over `.php` and `.html` files, because injected `<script>` tags usually land in `header.php` / `footer.php`.

**`--wp`** (per WordPress install, run as the account owner with `--skip-plugins --skip-themes`)
- `wp core verify-checksums` — files that shouldn't exist in `wp-admin` / `wp-includes` → HIGH, modified core files → HIGH
- `wp plugin verify-checksums --all` — extra files → HIGH, mismatches → MEDIUM (premium plugins are skipped by wp-cli)
- lists every administrator; flags `admin1` / `wp_support`-style logins and junk-TLD emails
- `wp_options` containing `<script`, `eval(`, `atob(`, `base64_decode`, `<iframe` → `[HIGH-DB]`
- `wp_posts` with external `<script src>`, `eval(atob`, hidden iframes → `[MED-DB]`
- prints `siteurl` / `home`

DB findings are report-only; the script never modifies the database.

**INFO**
- PHP/JS files modified in the last N days
- immutable (`chattr +i`) flags on hits — removed automatically before quarantining

## After the scan

The report ends with a checklist of what a file scanner can't do for you:

- rotate cPanel / FTP / WP admin / DB passwords and the salts in `wp-config.php`
- check `crontab -l -u <user>`, `~/.bashrc`, `~/.ssh/authorized_keys` for persistence
- check `wp_users` for rogue admins and `wp_options` for injected `siteurl` / `home` / `active_plugins`
- grep access logs for POSTs to the quarantined paths to find the entry point and attacker IPs
- update core, themes and plugins; remove the unused ones

Run it twice: once before `--quarantine`, and once after updating core/plugins, since checksum mismatches on an outdated install can include legitimate hotfixes.

## Notes

- Pairs well with `maldet` — different signature sets, they catch different things.
- `--wp` loads `wp-config.php` and mu-plugins as the account user. That's no worse than what every page load already does, but be aware of it on a compromised site.
- Files larger than 5 MB (PHP) / 3 MB (JS) are skipped for speed.

## License

MIT
