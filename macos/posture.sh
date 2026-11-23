#!/usr/bin/env bash
# macOS and Brave security posture, read-only and without sudo. Changes no setting.
#
#   macos/posture.sh        -> out/macos-posture-<date>.jsonl + OK/WARN/INFO/SKIP lines
#
# Each line: {check, status, detail}. Anything that needs admin rights is reported as SKIP.
set -u
cd "$(dirname "$0")/.." || exit 1
mkdir -p out
OUT="out/macos-posture-$(date +%F).jsonl"
: >"$OUT"
FW=/usr/libexec/ApplicationFirewall/socketfilterfw
BRAVE="$HOME/Library/Application Support/BraveSoftware/Brave-Browser"

json() { local s=$1; s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\t'/ }; s=${s//$'\r'/}; printf '"%s"' "$s"; }
emit() { printf '%-4s %-22s %s\n' "$2" "$1" "$3"; printf '{"check":%s,"status":%s,"detail":%s}\n' "$(json "$1")" "$(json "$2")" "$(json "$3")" >>"$OUT"; }
ok_if() { if eval "$2"; then emit "$1" OK "$3"; else emit "$1" WARN "$3"; fi; }

# Disk and boot
s=$(fdesetup status 2>&1 | head -1); ok_if filevault '[[ $s == *"is On"* ]]' "$s"
s=$(csrutil status 2>&1); ok_if sip '[[ $s == *enabled* ]]' "$s"
s=$(spctl --status 2>&1); ok_if gatekeeper '[[ $s == *"assessments enabled"* ]]' "$s"

# Application firewall
s=$($FW --getglobalstate 2>&1); ok_if firewall '[[ $s == *enabled* ]]' "$s"
s=$($FW --getstealthmode 2>&1); ok_if firewall-stealth '[[ $s == *" on"* || $s == *enabled* ]]' "$s"

# Updates: automatic settings and pending ones (softwareupdate can be slow, capped at 120 s)
SU=/Library/Preferences/com.apple.SoftwareUpdate
for k in AutomaticCheckEnabled AutomaticDownload CriticalUpdateInstall ConfigDataInstall AutomaticallyInstallMacOSUpdates; do
  v=$(defaults read "$SU" "$k" 2>/dev/null || echo "unset (default)")
  ok_if "update-$k" '[[ $v != 0 ]]' "$v"
done
v=$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null || echo "unset (default)")
ok_if update-appstore-apps '[[ $v != 0 ]]' "$v"
tmp=$(mktemp)
softwareupdate -l >"$tmp" 2>&1 & pid=$!
(sleep 120 && kill "$pid" 2>/dev/null) & watcher=$!
if wait "$pid" 2>/dev/null; then
  { kill "$watcher" && wait "$watcher"; } 2>/dev/null
  labels=$(grep -E '^\s*\* Label:' "$tmp" | sed 's/.*Label: //' | paste -sd ',' -)
  ver=$(sw_vers -productVersion)
  if [[ -z $labels ]]; then emit updates-pending OK "$ver, no pending updates"
  else emit updates-pending WARN "$ver, pending: $labels"; fi
else
  emit updates-pending SKIP "softwareupdate -l did not answer within 120 s"
fi
rm -f "$tmp"

# Screen and session
s=$(sysadminctl -screenLock status 2>&1 | sed 's/^.*\] //' | tail -1)
ok_if screen-lock '[[ $s == *immediate* || $s =~ delay\ is\ [0-9]+\ seconds && ${s//[^0-9]/} -le 5 ]]' "$s"
idle=$(defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null || echo "?")
dsleep=$(pmset -g 2>/dev/null | awk '$1=="displaysleep"{print $2}')
emit screensaver INFO "screensaver after ${idle} s, display off after ${dsleep:-?} min"
v=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
if [[ -n $v ]]; then emit auto-login WARN "automatic login as $v"; else emit auto-login OK off; fi
v=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo 0)
ok_if guest-account '[[ $v == 0 ]]' "GuestEnabled=$v"

# Sharing and remote access: systemsetup needs admin, listening ports do not.
s=$(systemsetup -getremotelogin 2>&1)
if [[ $s == *administrator* ]]; then emit remote-login SKIP "systemsetup needs admin; see listening ports below"
else ok_if remote-login '[[ $s == *Off* ]]' "$s"; fi
port_label() {
  case $1 in
    22) echo "SSH (Remote Login)" ;; 445) echo "SMB (File Sharing)" ;; 548) echo "AFP (File Sharing)" ;;
    3283) echo "Apple Remote Desktop" ;; 5900) echo "Screen Sharing/VNC" ;; 5000|7000) echo "AirPlay Receiver" ;; 3689) echo "Music Sharing" ;;
  esac
}
open=0
while read -r addr pid; do
  port=${addr##*.}
  name=$(ps -p "$pid" -o comm= 2>/dev/null | sed 's#.*/##'); name=${name:-pid $pid}
  label=$(port_label "$port")
  open=$((open + 1))
  if [[ -n $label || $name == sshd || $name == launchd ]]; then emit "listen-$port" WARN "$addr ($name) ${label:-system service}, reachable from the network"
  else emit "listen-$port" INFO "$addr ($name) reachable from the local network"; fi
done < <(netstat -anv -p tcp 2>/dev/null | awk '$6=="LISTEN" && $4 !~ /^(127\.|::1)/ && $4 !~ /%lo0/ {print $4, $11}' | sort -u -k1,1)
[[ $open == 0 ]] && emit listen OK "no TCP port listening outside loopback"

# Login and background items: sfltool dumpbtm works without sudo on macOS 13+.
btm=$(sfltool dumpbtm 2>/dev/null)
if [[ -n $btm ]]; then
  while IFS=$'\x1f' read -r name type ident exe team; do
    if [[ -z $team && $exe != /opt/homebrew/* ]]; then emit btm-item WARN "$name [$type] $ident $exe (no developer signature: check you recognise it)"
    else emit btm-item INFO "$name [$type] $ident $exe (Team $team)"; fi
  done < <(awk '
    function flush() { if (disp ~ /^\[enabled/ && type ~ /(agent|daemon|login item)/ && !seen[ident]++) print name "\037" type "\037" ident "\037" exe "\037" team; name=type=disp=ident=exe=team="" }
    /^ #[0-9]+:/ { flush() }
    /^ +Name:/ { sub(/^ +Name: /, ""); name=$0 }
    /^ +Type:/ { sub(/^ +Type: /, ""); sub(/ \(0x.*/, ""); type=$0 }
    /^ +Disposition:/ { sub(/^ +Disposition: /, ""); disp=$0 }
    /^ +Identifier:/ { sub(/^ +Identifier: /, ""); ident=$0 }
    /^ +Executable Path:/ { sub(/^ +Executable Path: /, ""); exe=$0 }
    /^ +Team Identifier:/ { sub(/^ +Team Identifier: /, ""); team=$0 }
    END { flush() }' <<<"$btm")
else
  emit btm SKIP "sfltool dumpbtm needs sudo here; falling back to launchctl and LaunchAgents"
  for d in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
    for f in "$d"/*.plist; do [[ -e $f ]] && emit launch-item INFO "$f"; done
  done
  launchctl list | awk 'NR>1 && $3 !~ /^com\.apple\./ {print $3}' | while read -r l; do emit launchctl INFO "$l"; done
fi

# Brave with --remote-debugging-port: any local process can drive the signed-in browser.
dbg=$(ps -axo command= | grep -E 'Brave Browser\.app/Contents/MacOS/Brave Browser( |$)' | grep -v grep | grep -oE -- '--remote-debugging-(port|address)=[^ ]+' | sort -u | paste -sd ' ' -)
if [[ -n $dbg ]]; then
  bind=$(netstat -an -p tcp 2>/dev/null | awk -v p="${dbg##*=}" '$6=="LISTEN" && $4 ~ "\\." p "$" {print $4}' | paste -sd ',' -)
  emit brave-remote-debugging WARN "$dbg listening on ${bind:-?}. The google-personal and connected-apps connectors need it, but while it is open any local process (an npm package, an editor extension) can read cookies and act as every signed-in account without asking. Start Brave without the flag when you are not using it."
else
  emit brave-remote-debugging OK "Brave is not running with --remote-debugging-port"
fi

# Brave extensions per profile with granted permissions. Flags broad host access and sensitive APIs.
if [[ -d $BRAVE ]]; then
  node - "$BRAVE" <<'JS' | while IFS=$'\t' read -r st check detail; do emit "$check" "$st" "$detail"; done
const fs = require("fs"), path = require("path");
const dir = process.argv[2];
const BROAD = /^(<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/\*|file:\/\/\/\*)$/;
const SENSITIVE = new Set(["cookies", "webRequest", "webRequestBlocking", "debugger", "proxy", "nativeMessaging", "history",
  "management", "privacy", "clipboardRead", "downloads", "declarativeNetRequestWithHostAccess", "scripting", "tabs", "webNavigation", "desktopCapture"]);
const read = (f) => { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch { return null; } };
for (const prof of fs.readdirSync(dir).filter((p) => p === "Default" || /^Profile \d+$/.test(p))) {
  const prefs = read(path.join(dir, prof, "Preferences"));
  const name = prefs?.profile?.name || prof;
  const settings = { ...prefs?.extensions?.settings, ...read(path.join(dir, prof, "Secure Preferences"))?.extensions?.settings };
  for (const [id, e] of Object.entries(settings)) {
    if (![1, 4, 6, 8].includes(e.location)) continue; // 1 web store, 4 unpacked, 6/8 external or command line
    const extDir = e.path ? (path.isAbsolute(e.path) ? e.path : path.join(dir, prof, "Extensions", e.path)) : null;
    const man = e.manifest || (extDir && read(path.join(extDir, "manifest.json"))) || {};
    let label = man.name || id;
    const msg = /^__MSG_(.+)__$/.exec(label);
    if (msg && extDir) {
      const m = read(path.join(extDir, "_locales", man.default_locale || "en", "messages.json")) || {};
      const k = Object.keys(m).find((k) => k.toLowerCase() === msg[1].toLowerCase());
      label = k ? m[k].message : label;
    }
    const act = e.active_permissions || e.granted_permissions || {};
    const api = act.api || man.permissions || [];
    const hosts = [...new Set([...(act.explicit_host || []), ...(act.scriptable_host || [])])];
    const broad = hosts.filter((x) => BROAD.test(x));
    const sens = api.filter((p) => SENSITIVE.has(p));
    const enabled = !(e.disable_reasons?.length || e.state === 0);
    const flags = [
      broad.length && `access to all sites (${broad.join(" ")})${e.withholding_permissions ? ", on click only" : ""}`,
      sens.length && `sensitive APIs: ${sens.join(", ")}`,
      e.location === 4 && "unpacked (developer mode)",
      !e.from_webstore && e.location !== 4 && "not from the Chrome Web Store",
    ].filter(Boolean);
    const warn = enabled && (broad.length && !e.withholding_permissions || e.location === 4 || sens.some((p) => ["debugger", "proxy", "nativeMessaging", "cookies", "webRequestBlocking"].includes(p)));
    const detail = `[${name}] ${label} (${id}) ${enabled ? "enabled" : "disabled"}, v${man.version || "?"}; hosts: ${hosts.length > 4 ? hosts.slice(0, 4).join(" ") + ` +${hosts.length - 4}` : hosts.join(" ") || "none"}${flags.length ? "; " + flags.join("; ") : ""}`;
    console.log([warn ? "WARN" : "INFO", "brave-extension", detail].join("\t"));
  }
}
JS
else
  emit brave-extensions SKIP "no Brave profile in $BRAVE"
fi

echo
echo "$(grep -c '"WARN"' "$OUT") WARN, $(grep -c '"OK"' "$OUT") OK, $(grep -c '"SKIP"' "$OUT") SKIP. Details: $OUT"
