#!/usr/bin/env bash
# webshell-hunter.sh — find and quarantine PHP backdoors / webshells on a web server.
#
# Default is REPORT ONLY (no changes). Use --quarantine to move hits out of the
# webroot (reversible), or --delete --yes to remove them (not reversible).
#
# Usage:
#   webshell-hunter.sh [options]
#     -p PATH        path to scan (repeatable; default: /home/*/public_html)
#     -d DAYS        also list files modified in the last DAYS days (default: 7)
#     -x PATTERN     exclude paths matching PATTERN (repeatable, grep -E syntax)
#     -o FILE        write report to FILE (default: /root/webshell-report-<ts>.txt)
#     --quarantine   move HIGH-severity hits to /root/quarantine/<ts>/ (reversible)
#     --all          with --quarantine/--delete: act on MEDIUM hits too
#     --delete       delete hits instead of quarantining (requires --yes)
#     --yes          don't ask for confirmation
#     --restore FILE restore files listed in a quarantine manifest, then exit
#     --wp           for every WordPress install found: run wp-cli checksum
#                    verification (core + plugins), look for rogue admins and
#                    script/eval injections in wp_options / wp_posts
#     --no-js        skip the JavaScript injection scan
#     -h             help
#
# Scans: PHP backdoors/webshells, PHP hidden in images/css/js, injected .htaccess
# and .user.ini, malicious/obfuscated JavaScript (redirects, hidden iframes,
# miners, skimmers, identical snippets appended across many .js files).
#
# Run as root. Tested on cPanel/WHM and CWP; works on any Linux with GNU grep/find.
# --wp needs wp-cli ("wp") in PATH; it runs as the account owner with
# --skip-plugins --skip-themes, but it still loads wp-config.php and mu-plugins.

set -uo pipefail

TS=$(date +%Y%m%d-%H%M%S)
QDIR_BASE="/root/quarantine"
REPORT="/root/webshell-report-${TS}.txt"
DAYS=7
MODE="report"          # report | quarantine | delete
ACT_ON_MEDIUM=0
ASSUME_YES=0
RESTORE_FILE=""
WP_CHECKS=0
JS_SCAN=1
declare -a SCAN_PATHS=()
declare -a EXCLUDES=()

# ---------- helpers ----------
red()    { printf '\033[31m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
log()    { printf '%s\n' "$*" | tee -a "$REPORT"; }
die()    { red "ERROR: $*" >&2; exit 1; }

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# ---------- args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p) SCAN_PATHS+=("$2"); shift 2 ;;
    -d) DAYS="$2"; shift 2 ;;
    -x) EXCLUDES+=("$2"); shift 2 ;;
    -o) REPORT="$2"; shift 2 ;;
    --quarantine) MODE="quarantine"; shift ;;
    --delete) MODE="delete"; shift ;;
    --all) ACT_ON_MEDIUM=1; shift ;;
    --yes) ASSUME_YES=1; shift ;;
    --restore) RESTORE_FILE="$2"; shift 2 ;;
    --wp) WP_CHECKS=1; shift ;;
    --no-js) JS_SCAN=0; shift ;;
    -h|--help) usage ;;
    *) die "unknown option: $1 (see -h)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root"
command -v grep >/dev/null || die "grep missing"
echo a | grep -qP 'a' 2>/dev/null || die "GNU grep with -P support required"

# ---------- restore mode ----------
if [[ -n "$RESTORE_FILE" ]]; then
  [[ -f "$RESTORE_FILE" ]] || die "manifest not found: $RESTORE_FILE"
  echo "Restoring from $RESTORE_FILE ..."
  # manifest line format: <sha256>|<owner>:<group>|<mode>|<original_path>|<quarantine_path>
  while IFS='|' read -r sha own mode orig qpath; do
    [[ -z "$orig" || "$sha" == \#* ]] && continue
    if [[ ! -f "$qpath" ]]; then yellow "missing in quarantine: $qpath"; continue; fi
    mkdir -p "$(dirname "$orig")"
    mv -f "$qpath" "$orig" && chown "$own" "$orig" && chmod "$mode" "$orig" \
      && green "restored: $orig" || red "failed: $orig"
  done < "$RESTORE_FILE"
  exit 0
fi

# ---------- default scan paths ----------
if [[ ${#SCAN_PATHS[@]} -eq 0 ]]; then
  shopt -s nullglob
  for d in /home/*/public_html /home/*/domains/*/public_html /var/www /usr/local/apache/htdocs; do
    [[ -d "$d" ]] && SCAN_PATHS+=("$d")
  done
  shopt -u nullglob
fi
[[ ${#SCAN_PATHS[@]} -gt 0 ]] || die "no scan paths found; pass -p"

[[ "$MODE" == "delete" && $ASSUME_YES -eq 0 ]] && die "--delete requires --yes"

: > "$REPORT"
log "# webshell-hunter report  $(date)"
log "# host: $(hostname)  mode: $MODE  paths: ${SCAN_PATHS[*]}"
log ""

# ---------- signatures ----------
# HIGH: near-certain backdoor/webshell indicators. Each is a PCRE for grep -P.
HIGH_SIGS=(
  'eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|rawurldecode|urldecode|hex2bin|convert_uudecode)\s*\('
  '(eval|assert|system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)|\$\{)'
  'preg_replace\s*\(\s*["\x27][^"\x27]*/[a-zA-Z]*e[a-zA-Z]*["\x27]'
  'FilesMan|FilesTooLs|Sec-Info|c99sh|c99shell|r57shell|WSO\s*[0-9.]*\s*</title|b374k|Priv8|IndoXploit|AnonymousFox|Mister\s?Spy|alfa\s?shell|ALFA_DATA|wso\.php|p0wny|Gel4y|0byt3m1n1'
  '\$\w+\s*=\s*["\x27]\w+["\x27]\s*;\s*\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'  # $f="system"; $f($_GET[..])
  'move_uploaded_file\s*\(\s*\$_FILES\[[^\]]+\]\[.tmp_name.\]\s*,\s*\$_(GET|POST|REQUEST)'
  '@?\$_(GET|POST|REQUEST|COOKIE)\[[^\]]+\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'     # $_GET[a]($_GET[b])
  'array_map\s*\(\s*["\x27](assert|system|eval|passthru)["\x27]'
  'base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
  'file_put_contents\s*\(\s*\$_(GET|POST|REQUEST)\[[^\]]+\]\s*,\s*(\$_(GET|POST|REQUEST)|base64_decode)'
  '(ini_set\s*\(\s*["\x27](display_errors|error_log)["\x27]|error_reporting\s*\(\s*0\s*\))\s*;\s*@?\$\w+\s*=\s*\$_(GET|POST|COOKIE)'
  'create_function\s*\(\s*["\x27]["\x27]\s*,\s*(base64_decode|gzinflate|\$_)'
)

# MEDIUM: obfuscation / suspicious constructs; common in malware, occasionally in legit code.
MEDIUM_SIGS=(
  '(gzinflate|gzuncompress|str_rot13)\s*\(\s*base64_decode\s*\('
  'base64_decode\s*\(\s*["\x27][A-Za-z0-9+/=]{200,}["\x27]\s*\)'
  '(\\x[0-9a-fA-F]{2}){12,}'                                 # long hex-escaped strings
  '(chr\s*\(\s*\d+\s*\)\s*\.\s*){8,}'                        # chr(1).chr(2)... concat
  '\$GLOBALS\[\s*["\x27]\w+["\x27]\s*\]\s*\[\s*\d+\s*\]\s*\.'  # $GLOBALS['x'][12].$GLOBALS['x'][5]
  'goto\s+\w+;\s*\w+:\s*' 
  '(assert|eval)\s*\(\s*(\$\w+|gzinflate|base64_decode|str_rot13|strrev)'
  'extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
  'php_uname|posix_getpwuid|safe_mode|disable_functions|open_basedir|@set_time_limit\s*\(\s*0\s*\)'
  'wp_set_auth_cookie\s*\(\s*1\s*\)|wp_insert_user\s*\(\s*array\s*\(\s*["\x27]user_login'
  '<\?php\s+@?(eval|assert|include|require)(_once)?\s*\(?\s*\$_'
)

# Suspicious filenames (regex on basename)
NAME_SIGS='^(\.?[a-z0-9]{1,3}|\.[a-z]+|[a-f0-9]{8,}|wp-(conf|up|cache|inc|file|load)[a-z0-9_-]*|class-wp-[a-z]*-[a-z0-9]{5,}|about|lock|xleet|radio|sym|up|shell|cmd|ws0|wso\d*|c99|r57|alfa|mini|marijuana|indoxploit|adminer|admin\d+|install\d+|xml\d+|config\d+|link|wp-login\d+)\.php$'

# ---------- JavaScript signatures ----------
# Scanned in .js files AND inside .php/.html/.htm (inline <script> injections).
JS_HIGH_SIGS=(
  '(eval|Function|setTimeout|setInterval)\s*\(\s*(atob|unescape|decodeURIComponent|window\.atob)\s*\('   # eval(atob(...))
  'new\s+Function\s*\(\s*(atob|unescape|decodeURIComponent)\s*\('
  'document\.write(ln)?\s*\(\s*(unescape|atob|decodeURIComponent|String\.fromCharCode)\s*\('
  'window\.location(\.href|\.replace|\.assign)?\s*(=|\()\s*(atob|unescape|decodeURIComponent)\s*\('     # encoded redirect
  '<iframe[^>]*\s(width|height)\s*=\s*["\x27]?\s*[01]\s*(px)?["\x27]?[^>]*>|<iframe[^>]*style\s*=\s*["\x27][^"\x27]*(display\s*:\s*none|visibility\s*:\s*hidden|position\s*:\s*absolute\s*;\s*(left|top)\s*:\s*-\d{3,})'  # hidden iframe
  'coinhive|CoinHive|coin-hive|cryptonight|CryptoNight|minero\.cc|webminepool|crypto-loot|cryptoloot|jsecoin|authedmine|deepMiner|CoinImp|monerominer|WMP\.start\s*\('   # miners
  '(new\s+Image\s*\(\s*\)|\.src)\s*[=.][^;\n]{0,120}(document\.cookie|localStorage)'                   # cookie exfil
  '(cc[_-]?num|card[_-]?number|cardnumber|cvv|cvc|expir)[^\n]{0,200}(btoa|encodeURIComponent)\s*\([^\n]{0,200}(fetch|XMLHttpRequest|\.src\s*=|sendBeacon)'  # skimmer
  'String\.fromCharCode\s*\(\s*\d+\s*(,\s*\d+\s*){40,}\)\s*\)?\s*\)?\s*;?\s*\n?[^\n]{0,40}(eval|Function|document\.write|location)'
  '(\\x[0-9a-fA-F]{2}){16,}[^\n]{0,400}(eval|Function|document\.write|location|appendChild)'           # hex-obfuscated + exec
  '\\x65\\x76\\x61\\x6c|\\x61\\x74\\x6f\\x62|\\x75\\x6e\\x65\\x73\\x63\\x61\\x70\\x65|\\x66\\x72\\x6f\\x6d\\x43\\x68\\x61\\x72'  # hex-encoded "eval"/"atob"/"unescape"/"fromChar"
  '\\u0065\\u0076\\u0061\\u006c|\\u0061\\u0074\\u006f\\u0062'                                      # unicode-escaped "eval"/"atob"
)
JS_MED_SIGS=(
  '_0x[a-f0-9]{4,}\s*(\(|\[)[^\n]{0,300}(eval|Function|location|document\.write|createElement\s*\(\s*["\x27]script)'  # javascript-obfuscator output doing exec
  'String\.fromCharCode\s*\(\s*\d+\s*(,\s*\d+\s*){20,}'
  '(\\u00[0-9a-fA-F]{2}){16,}'
  'atob\s*\(\s*["\x27][A-Za-z0-9+/=]{100,}["\x27]\s*\)'
  'createElement\s*\(\s*["\x27]script["\x27]\s*\)[^\n]{0,300}\.src\s*=\s*[^\n]{0,80}(atob|unescape|fromCharCode|\+\s*["\x27][a-z0-9]{6,}["\x27])'  # dynamically built script src
  '<script[^>]*\ssrc\s*=\s*["\x27]?(https?:)?//[^"\x27\s>]*\.(tw|top|xyz|club|icu|cfd|sbs|buzz|gq|ml|cf|tk|ga|rest|pw|bar|monster|quest|skin|boats|lol|zip|mov)(/|["\x27\s>])'  # script from throwaway TLD
  'navigator\.userAgent[^\n]{0,200}(bot|google|bing|yandex)[^\n]{0,300}(location|document\.write|createElement)'   # cloaked redirect
  '(document\.referrer|navigator\.userAgent)[^\n]{0,150}(indexOf|test|match)[^\n]{0,200}location\.(href|replace)\s*(=|\()'
  'window\s*\[\s*(["\x27]\\x[0-9a-f]{2}|_0x\w+\s*\[|\w+\s*\[\s*\d+\s*\]\s*\]\s*\()'                  # window["\x65.."] / window[_0x1a[0]](...)
  'document\.cookie\s*\+?=\s*["\x27][^"\x27]{1,40}=1[^"\x27]*expires[^\n]{0,200}location'              # set cookie once + redirect
)

PHP_EXT_REGEX='.*\.(php[0-9]?|phtml|phar|inc|pht|phps)$'
JS_EXT_REGEX='.*\.(js|mjs|cjs|htm|html|xhtml)$'
IMG_EXT_REGEX='.*\.(ico|jpg|jpeg|png|gif|svg|css|js|txt|log|dat|json|xml|pdf|woff|ttf|bak|old|tmp)$'

# ---------- build find prune list ----------
EXCL_RE=""
if [[ ${#EXCLUDES[@]} -gt 0 ]]; then EXCL_RE=$(IFS='|'; echo "${EXCLUDES[*]}"); fi
filter_excl() { if [[ -n "$EXCL_RE" ]]; then grep -Ev "$EXCL_RE"; else cat; fi; }

TMP=$(mktemp -d /tmp/wsh.XXXXXX); trap 'rm -rf "$TMP"' EXIT
HIGH_HITS="$TMP/high"; MED_HITS="$TMP/med"; INFO_HITS="$TMP/info"
: > "$HIGH_HITS"; : > "$MED_HITS"; : > "$INFO_HITS"

add_hit() { # file reason severity
  local f="$1" why="$2" sev="$3"
  case "$sev" in
    HIGH) grep -qxF "$f" <(cut -f1 "$HIGH_HITS") || printf '%s\t%s\n' "$f" "$why" >> "$HIGH_HITS" ;;
    MED)  grep -qxF "$f" <(cut -f1 "$HIGH_HITS" "$MED_HITS") || printf '%s\t%s\n' "$f" "$why" >> "$MED_HITS" ;;
    INFO) printf '%s\t%s\n' "$f" "$why" >> "$INFO_HITS" ;;
  esac
}

# ---------- 1. collect candidate files ----------
echo "[*] Collecting files from ${#SCAN_PATHS[@]} path(s)..."
PHP_LIST="$TMP/php.list"; OTHER_LIST="$TMP/other.list"; RECENT_LIST="$TMP/recent.list"; JS_LIST="$TMP/js.list"
find "${SCAN_PATHS[@]}" -type f -size -5M -regextype posix-extended -iregex "$PHP_EXT_REGEX" 2>/dev/null | filter_excl > "$PHP_LIST"
find "${SCAN_PATHS[@]}" -type f -size -2M -regextype posix-extended -iregex "$IMG_EXT_REGEX" 2>/dev/null | filter_excl > "$OTHER_LIST"
find "${SCAN_PATHS[@]}" -type f -size -3M -regextype posix-extended -iregex "$JS_EXT_REGEX" 2>/dev/null | filter_excl > "$JS_LIST"
find "${SCAN_PATHS[@]}" -type f -regextype posix-extended \( -iregex "$PHP_EXT_REGEX" -o -iregex "$JS_EXT_REGEX" \) -mtime "-$DAYS" 2>/dev/null | filter_excl > "$RECENT_LIST"
echo "    $(wc -l < "$PHP_LIST") PHP, $(wc -l < "$JS_LIST") JS/HTML, $(wc -l < "$OTHER_LIST") other files; $(wc -l < "$RECENT_LIST") PHP/JS files modified in last $DAYS days"

# ---------- 2. signature scan on PHP ----------
echo "[*] Scanning PHP files for HIGH-confidence signatures..."
i=0
for sig in "${HIGH_SIGS[@]}"; do
  i=$((i+1))
  xargs -a "$PHP_LIST" -d '\n' -r grep -lP -- "$sig" 2>/dev/null | while IFS= read -r f; do add_hit "$f" "HIGH sig #$i" HIGH; done
done

echo "[*] Scanning PHP files for MEDIUM (obfuscation) signatures..."
i=0
for sig in "${MEDIUM_SIGS[@]}"; do
  i=$((i+1))
  xargs -a "$PHP_LIST" -d '\n' -r grep -lP -- "$sig" 2>/dev/null | while IFS= read -r f; do add_hit "$f" "MED sig #$i" MED; done
done

# ---------- 3. PHP code hidden in non-PHP files ----------
echo "[*] Checking non-PHP files (images, css, js, txt...) for embedded PHP..."
xargs -a "$OTHER_LIST" -d '\n' -r grep -lP '<\?php|<\?=\s*\$|<script\s+language\s*=\s*["\x27]php' 2>/dev/null \
  | while IFS= read -r f; do
      # svg/txt/log can legitimately contain the string; still flag, but as MED unless it also has exec funcs
      if grep -qP '(eval|assert|system|passthru|shell_exec|base64_decode)\s*\(' "$f" 2>/dev/null; then
        add_hit "$f" "PHP code with exec/eval inside non-PHP file" HIGH
      else
        add_hit "$f" "PHP tag inside non-PHP file" MED
      fi
    done

# ---------- 4. PHP in places it should never be ----------
echo "[*] Checking PHP files in upload/cache directories..."
while IFS= read -r f; do
      rel="$f"; for sp in "${SCAN_PATHS[@]}"; do [[ "$f" == "$sp"/* ]] && { rel="/${f#"$sp"/}"; break; }; done
      grep -qP '/(wp-content/uploads|wp-content/cache|wp-content/upgrade|images|img|uploads|upload|files|media|cache|tmp|temp|backup|backups|assets)/' <<<"$rel" || continue
      grep -qP '/(cache|wp-content/cache)/.*/(cache-|index\.php$)' <<<"$rel" && continue
      # index.php in uploads that only contains "<?php // Silence is golden" is WordPress default
      if [[ "$(basename "$f")" == "index.php" ]] && grep -qi 'silence is golden' "$f" 2>/dev/null; then continue; fi
      add_hit "$f" "PHP in upload/cache dir" MED
done < "$PHP_LIST"

# ---------- 5. suspicious filenames ----------
echo "[*] Checking suspicious filenames..."
while IFS= read -r f; do
  bn=$(basename "$f")
  if [[ "$bn" =~ $NAME_SIGS ]]; then add_hit "$f" "suspicious filename" MED; fi
done < "$PHP_LIST"

# ---------- 6. .htaccess injections ----------
echo "[*] Checking .htaccess files..."
find "${SCAN_PATHS[@]}" -type f -name .htaccess 2>/dev/null | filter_excl | while IFS= read -r f; do
  # NB: cPanel MultiPHP legitimately writes "AddHandler application/x-httpd-ea-phpXX .php" — only flag when PHP handler is mapped to non-PHP extensions
  if grep -qP '(AddHandler|AddType|SetHandler)\s+\S*php\S*\s+[^\n]*\.(ico|png|jpe?g|gif|txt|css|js|svg|xml|json|html?|log|dat)\b|php_value\s+auto_(prepend|append)_file|RewriteRule.*\.(ico|png|jpg|gif)\s+.*\.php|RewriteCond\s+%\{HTTP_USER_AGENT\}.*(google|bing|yahoo).*\n?.*RewriteRule' "$f" 2>/dev/null; then
    add_hit "$f" ".htaccess: handler/prepend/SEO-redirect injection" HIGH
  fi
  if grep -qP '^\s*<Files(Match)?\s+["\x27]?\.?[a-z0-9_-]+\.(ico|png|jpg|txt|css)["\x27]?>\s*$' "$f" 2>/dev/null; then
    add_hit "$f" ".htaccess: Files block for non-PHP (likely allows shell)" MED
  fi
done

# ---------- 7. .user.ini / php.ini auto_prepend ----------
find "${SCAN_PATHS[@]}" -type f \( -name .user.ini -o -name php.ini \) 2>/dev/null | filter_excl | while IFS= read -r f; do
  grep -qP '^\s*auto_(prepend|append)_file\s*=' "$f" 2>/dev/null && add_hit "$f" "auto_prepend/append_file set" HIGH
done

# ---------- 7b. JavaScript injections ----------
if [[ $JS_SCAN -eq 1 ]]; then
  echo "[*] Scanning JS/HTML/PHP for malicious JavaScript..."
  JS_TARGETS="$TMP/js.targets"; cat "$JS_LIST" "$PHP_LIST" > "$JS_TARGETS"   # inline <script> injections land in PHP/HTML too
  i=0
  for sig in "${JS_HIGH_SIGS[@]}"; do
    i=$((i+1))
    xargs -a "$JS_TARGETS" -d '\n' -r grep -lP -- "$sig" 2>/dev/null | while IFS= read -r f; do add_hit "$f" "JS HIGH sig #$i" HIGH; done
  done
  i=0
  for sig in "${JS_MED_SIGS[@]}"; do
    i=$((i+1))
    xargs -a "$JS_TARGETS" -d '\n' -r grep -lP -- "$sig" 2>/dev/null | while IFS= read -r f; do add_hit "$f" "JS MED sig #$i" MED; done
  done

  # .js files in upload dirs (WordPress blocks .js uploads by default)
  while IFS= read -r f; do
    rel="$f"; for sp in "${SCAN_PATHS[@]}"; do [[ "$f" == "$sp"/* ]] && { rel="/${f#"$sp"/}"; break; }; done
    grep -qP '/(wp-content/uploads|uploads|upload|media|files)/.*\.(js|mjs)$' <<<"$rel" && add_hit "$f" "JS file in upload dir" MED
  done < "$JS_LIST"

  # Same suspicious snippet prepended/appended to many .js files (Balada / SocGholish style mass injection)
  echo "[*] Looking for identical snippets injected across many JS files..."
  TAILS="$TMP/js.tails"; : > "$TAILS"
  while IFS= read -r f; do
    case "$f" in *.js|*.mjs|*.cjs) ;; *) continue ;; esac
    for side in head tail; do
      if [[ $side == head ]]; then t=$(head -c 400 -- "$f" 2>/dev/null | tr -d '\n\r ')
      else t=$(tail -c 400 -- "$f" 2>/dev/null | tr -d '\n\r '); fi
      [[ ${#t} -lt 80 ]] && continue
      # only snippets that do something network/exec-ish; "})();" boilerplate alone is normal minified output
      grep -qP 'eval|atob|fromCharCode|location|iframe|https?:|createElement|appendChild|\\x[0-9a-f]{2}' <<<"$t" || continue
      # ignore common build-tool headers/footers and license banners
      grep -qP 'sourceMappingURL|webpackJsonp|webpackChunk|define\.amd|module\.exports|\(jQuery\)\s*;?$|\(window,document\)\s*;?$|^/\*!|@license|Copyright|MIT' <<<"$t" && continue
      # isolate the injected statement: head -> up to first self-invoking-function end; tail -> from last statement start
      if [[ $side == head ]]; then t=$(sed -E 's/(\}\)\(\);?|\)\(\);|\}\);).*/\1/' <<<"$t"); t="${t:0:300}"
      else t=$(sed -E 's/.*;(\(function|!function|\(\(\)=>|\(\)=>|var _0x|var _[a-z0-9]+=\[)/;\1/' <<<"$t"); [[ ${#t} -gt 300 ]] && t="${t: -300}"; fi
      [[ ${#t} -lt 60 ]] && continue
      printf '%s\t%s\t%s\n' "$(printf '%s' "$t" | md5sum | cut -d' ' -f1)" "$side" "$f" >> "$TAILS"
    done
  done < "$JS_LIST"
  cut -f1,2 "$TAILS" | sort | uniq -c | awk '$1>=5{print $2"\t"$3}' | while IFS=$'\t' read -r h side; do
    n=$(grep -c "^$h	$side	" "$TAILS")
    grep "^$h	$side	" "$TAILS" | cut -f3 | while IFS= read -r f; do add_hit "$f" "identical suspicious snippet at $side of $n JS files (mass injection)" MED; done
  done
fi

# ---------- 7c. WordPress checks via wp-cli ----------
if [[ $WP_CHECKS -eq 1 ]]; then
  if ! command -v wp >/dev/null; then
    yellow "wp-cli not found in PATH; skipping --wp checks"; log "NOTE: --wp requested but wp-cli not installed"
  else
    echo "[*] Running WordPress checks (wp-cli)..."
    find "${SCAN_PATHS[@]}" -maxdepth 4 -type f -name wp-config.php 2>/dev/null | filter_excl | while IFS= read -r cfg; do
      wpdir=$(dirname "$cfg"); [[ -f "$wpdir/wp-load.php" ]] || wpdir="$wpdir/$(cd "$wpdir" && ls -d */ 2>/dev/null | head -1)"
      [[ -f "$wpdir/wp-load.php" ]] || continue
      owner=$(stat -c '%U' "$cfg")
      WP="sudo -u $owner -- wp --path=$wpdir --skip-plugins --skip-themes --no-color"
      log ""; log "### WordPress: $wpdir (owner $owner)"

      # core checksums
      out=$($WP core verify-checksums 2>&1)
      echo "$out" | grep -P "File should not exist" | sed -E 's/.*File should not exist: //' | while IFS= read -r rel; do
        f="$wpdir/$rel"; [[ -f "$f" ]] || continue
        if [[ "$rel" == wp-admin/* || "$rel" == wp-includes/* ]]; then add_hit "$f" "wp core: file should not exist" HIGH
        else add_hit "$f" "wp core: unexpected file in root" MED; fi
      done
      echo "$out" | grep -P "doesn't verify against checksum" | sed -E "s/.*checksum: //" | while IFS= read -r rel; do
        f="$wpdir/$rel"; [[ -f "$f" ]] && add_hit "$f" "wp core: checksum mismatch (modified core file)" HIGH
      done
      echo "$out" | grep -qi "verifies against checksums" && log "  core: OK"

      # plugin checksums (only works for wordpress.org plugins; premium ones are skipped by wp-cli)
      out=$($WP plugin verify-checksums --all --format=csv 2>/dev/null | tail -n +2)
      echo "$out" | awk -F, 'NF>=3{print $1","$2","$3}' | while IFS=, read -r plugin rel msg; do
        f="$wpdir/wp-content/plugins/$plugin/$rel"; [[ -f "$f" ]] || continue
        case "$msg" in
          *"should not exist"*) add_hit "$f" "wp plugin $plugin: file should not exist" HIGH ;;
          *"doesn't verify"*|*"Checksum does not match"*) add_hit "$f" "wp plugin $plugin: checksum mismatch" MED ;;
        esac
      done

      # rogue admins
      $WP user list --role=administrator --fields=ID,user_login,user_email,user_registered --format=csv 2>/dev/null | tail -n +2 | while IFS= read -r l; do
        log "  admin user: $l"
      done

      # DB injections
      p=$($WP db prefix 2>/dev/null); p=${p:-wp_}
      $WP db query --skip-column-names "SELECT CONCAT('wp_options:',option_name) FROM ${p}options WHERE option_value REGEXP '<script|eval\\\\(|base64_decode|atob\\\\(|fromCharCode|<iframe' AND option_name NOT IN ('rewrite_rules')" 2>/dev/null \
        | while IFS= read -r l; do [[ -n "$l" ]] && log "  [HIGH-DB] $l  (script/eval in option — inspect with: wp option get <name>)"; done
      $WP db query --skip-column-names "SELECT CONCAT('wp_posts:',ID,' (',post_type,') ',post_title) FROM ${p}posts WHERE post_status IN ('publish','draft') AND post_content REGEXP '<script[^>]*src=|eval\\\\(atob|fromCharCode|<iframe[^>]*(display:none|width=\"?0)'" 2>/dev/null \
        | while IFS= read -r l; do [[ -n "$l" ]] && log "  [MED-DB]  $l  (script tag in content — check for injection)"; done
      $WP db query --skip-column-names "SELECT CONCAT('wp_users:',ID,' ',user_login,' ',user_email) FROM ${p}users WHERE user_login REGEXP '^(wp|admin|support|backup)[0-9_-]*$' OR user_email LIKE '%@%.(tk|ml|ga|cf|gq|xyz|top|icu)'" 2>/dev/null \
        | while IFS= read -r l; do [[ -n "$l" ]] && log "  [MED-DB]  $l  (suspicious user)"; done
      for o in siteurl home; do v=$($WP option get "$o" 2>/dev/null); [[ -n "$v" ]] && log "  $o = $v"; done
    done
  fi
fi

# ---------- 8. info: recently modified, immutable, odd perms ----------
echo "[*] Collecting informational findings..."
while IFS= read -r f; do add_hit "$f" "modified <${DAYS}d ago" INFO; done < "$RECENT_LIST"
if command -v lsattr >/dev/null; then
  while IFS= read -r f; do
    lsattr -d -- "$f" 2>/dev/null | grep -q '^....i' && add_hit "$f" "IMMUTABLE attr set (chattr -i before removing)" INFO
  done < <(cat "$HIGH_HITS" "$MED_HITS" | cut -f1)
fi

# ---------- 9. report ----------
NH=$(wc -l < "$HIGH_HITS"); NM=$(wc -l < "$MED_HITS"); NI=$(wc -l < "$INFO_HITS")
log "## HIGH ($NH) — almost certainly malicious"
while IFS=$'\t' read -r f why; do
  log "  [HIGH] $f  ($why)  owner=$(stat -c '%U' "$f" 2>/dev/null) mtime=$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)"
done < <(sort -u "$HIGH_HITS")
log ""
log "## MEDIUM ($NM) — review manually before acting"
while IFS=$'\t' read -r f why; do
  log "  [MED]  $f  ($why)"
done < <(sort -u "$MED_HITS")
log ""
log "## INFO ($NI) — context (recent changes, immutable flags)"
sort -u "$INFO_HITS" | awk -F'\t' '{printf "  [INFO] %s  (%s)\n",$1,$2}' | tee -a "$REPORT" | head -200
[[ $NI -gt 200 ]] && log "  ... ($((NI-200)) more in report file)"
log ""

if [[ $NH -eq 0 && $NM -eq 0 ]]; then green "No webshell signatures found."; log "Result: clean"; echo "Report: $REPORT"; exit 0; fi

# ---------- 10. act ----------
ACT_LIST="$TMP/act"
cut -f1 "$HIGH_HITS" | sort -u > "$ACT_LIST"
[[ $ACT_ON_MEDIUM -eq 1 ]] && cut -f1 "$MED_HITS" | sort -u >> "$ACT_LIST"
NA=$(sort -u "$ACT_LIST" | wc -l)

if [[ "$MODE" == "report" ]]; then
  yellow "Report only. Re-run with --quarantine to move $NH HIGH hits out of the webroot (add --all for MEDIUM too)."
  echo "Report: $REPORT"; exit 0
fi

echo
red "About to $MODE $NA file(s)."
if [[ $ASSUME_YES -eq 0 ]]; then
  read -r -p "Continue? [y/N] " ans; [[ "$ans" =~ ^[Yy]$ ]] || { echo "aborted"; exit 1; }
fi

QDIR="$QDIR_BASE/$TS"; MANIFEST="$QDIR/MANIFEST.txt"
if [[ "$MODE" == "quarantine" ]]; then
  mkdir -p "$QDIR" && chmod 700 "$QDIR"
  echo "# sha256|owner:group|mode|original_path|quarantine_path" > "$MANIFEST"
fi

while IFS= read -r f; do
  [[ -f "$f" ]] || continue
  lsattr -d -- "$f" 2>/dev/null | grep -q '^....i' && chattr -i -- "$f" 2>/dev/null
  own=$(stat -c '%U:%G' "$f"); mode=$(stat -c '%a' "$f"); sha=$(sha256sum "$f" | cut -d' ' -f1)
  if [[ "$MODE" == "quarantine" ]]; then
    dest="$QDIR/${f#/}"; mkdir -p "$(dirname "$dest")"
    if mv -- "$f" "$dest"; then
      chmod 000 "$dest"; echo "$sha|$own|$mode|$f|$dest" >> "$MANIFEST"
      log "  quarantined: $f -> $dest"
    else log "  FAILED to move: $f"; fi
  else
    log "  sha256=$sha owner=$own mode=$mode"
    rm -f -- "$f" && log "  deleted: $f" || log "  FAILED to delete: $f"
  fi
done < <(sort -u "$ACT_LIST")

echo
[[ "$MODE" == "quarantine" ]] && green "Done. Restore with:  $0 --restore $MANIFEST"
echo "Report: $REPORT"
log ""
log "## Post-cleanup checklist"
log "  - rotate: cPanel/FTP/WP admin/DB passwords, salts in wp-config.php"
log "  - check: crontab -l -u <user>, ~/.bashrc, ~/.ssh/authorized_keys for persistence"
log "  - check: wp_users for rogue admins, wp_options for injected siteurl/home/active_plugins"
log "  - check: access logs for POSTs to the quarantined paths (find entry point / IPs)"
log "  - update: WordPress core, themes, plugins; remove unused ones"
[[ $WP_CHECKS -eq 0 ]] && log "  - re-run with --wp for core/plugin checksum verification, rogue admins and DB injections"
