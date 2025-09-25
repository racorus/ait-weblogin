#!/usr/bin/env bash
# AITNet captive portal helper (login/logout/status) — no extra packages
# Usage:
#   sudo ait-weblogin.sh login              # login once (skips if already online)
#   sudo ait-weblogin.sh login --force      # login regardless of status
#   sudo ait-weblogin.sh logout             # explicit logout
#   sudo ait-weblogin.sh relogin            # logout (ignore errors) then login
#   sudo ait-weblogin.sh status             # show portal/internet status
# Optional: IFACE=<egress-nic> to renew DHCP after login/logout (e.g., IFACE=eno1)

set -euo pipefail
export LC_ALL=C

PORTAL_URL="https://aitnet.ait.ac.th/"
LOGIN_URL="https://aitnet.ait.ac.th/index.pl"
LOGOUT_URL="https://aitnet.ait.ac.th/logout-mod.pl"
CREDS_FILE="/root/.ait_login"
IFACE="${IFACE:-}"   # e.g., eno1 / enp3s0 / vmbr0

UA="Mozilla/5.0"

log(){ echo "[$(date '+%F %T')] $*"; }
die(){ log "[ERROR] $*"; exit 1; }

# ---------- connectivity probes ----------
has_full_internet() {
  getent hosts example.com >/dev/null 2>&1 || return 1
  _ok() {
    local url="$1"
    local out code final
    out="$(curl -s -L -o /dev/null -w "%{http_code} %{url_effective}" --max-time 8 "$url" || echo '000 x')"
    code="${out%% *}"; final="${out#* }"
    [[ "$code" =~ ^(2|3)[0-9][0-9]$ ]] && [[ "$final" != *"aitnet.ait.ac.th"* ]]
  }
  _ok "https://www.google.com/generate_204" && _ok "https://example.com"
}

show_status() {
  echo -n "[HTTPS probe] "
  curl -s -L -o /dev/null -w "%{http_code} %{url_effective}\n" https://www.google.com/generate_204
  echo -n "[HTTP probe ] "
  curl -s -L -o /dev/null -w "%{http_code} %{url_effective}\n" http://neverssl.com
  echo -n "[DNS probe  ] "
  getent hosts example.com | head -n1 || true
  echo -n "[Route     ] "
  ip route get 8.8.8.8 2>/dev/null | sed -E 's/ +/ /g' || true
}

# ---------- helpers ----------
urlencode() {
  local s="$1" out="" i c
  for (( i=0; i<${#s}; i++ )); do
    c=${s:$i:1}
    case "$c" in [a-zA-Z0-9._~-]) out+="$c" ;; ' ') out+='%20' ;;
      *) printf -v out '%s%%%02X' "$out" "'$c" ;;
    esac
  done
  printf '%s' "$out"
}

dns_dhcp_refresh() {
  if command -v resolvectl >/dev/null 2>&1; then
    log "[INFO] Flushing DNS cache…"; resolvectl flush-caches || true
  elif command -v systemd-resolve >/dev/null 2>&1; then
    log "[INFO] Flushing DNS cache…"; systemd-resolve --flush-caches || true
  fi
  if [[ -n "$IFACE" ]] && command -v dhclient >/dev/null 2>&1; then
    log "[INFO] DHCP renew on $IFACE…"
    dhclient -4 -r "$IFACE" || true; sleep 1; dhclient -4 "$IFACE" || true; sleep 1
  fi
}

require_creds() {
  [[ -f "$CREDS_FILE" ]] || die "Missing $CREDS_FILE with AIT_USER/AIT_PASS"
  # shellcheck disable=SC1090
  source "$CREDS_FILE"
  [[ -n "${AIT_USER:-}" && -n "${AIT_PASS:-}" ]] || die "Empty AIT_USER/AIT_PASS in $CREDS_FILE"
}

# ---------- login / logout ----------
do_login() {
  local force="${1:-0}"
  if has_full_internet && [[ "$force" -ne 1 ]]; then
    log "[OK] Already online; skipping login."
    return 0
  fi
  require_creds
  local wd cook page hdr resp hash redir hostv rc
  wd="$(mktemp -d)"; cook="$wd/c.txt"; page="$wd/p.html"; hdr="$wd/h.txt"; resp="$wd/r.html"
  trap 'rm -rf "$wd"' RETURN

  log "[INFO] GET $PORTAL_URL"
  curl -fsSL -c "$cook" -A "$UA" "$PORTAL_URL" -o "$page"

  hash="$(grep -o 'id="hash"[^>]*value="[^"]*"' "$page" | sed -E 's/.*value="([^"]*)".*/\1/' | head -n1 || true)"
  redir="$(grep -o 'id="redir"[^>]*value="[^"]*"' "$page" | sed -E 's/.*value="([^"]*)".*/\1/' | head -n1 || true)"
  hostv="$(grep -o 'id="host"[^>]*value="[^"]*"' "$page" | sed -E 's/.*value="([^"]*)".*/\1/' | head -n1 || true)"

  local data="username=$(urlencode "$AIT_USER")&password=$(urlencode "$AIT_PASS")"
  [[ -n "$hash"  ]] && data+="&hash=$(urlencode "$hash")"
  [[ -n "$redir" ]] && data+="&redir=$(urlencode "$redir")"
  [[ -n "$hostv" ]] && data+="&host=$(urlencode "$hostv")"

  log "[INFO] POST $LOGIN_URL"
  set +e
  curl -fsS -b "$cook" -c "$cook" -L \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Origin: https://aitnet.ait.ac.th" \
    -H "Referer: https://aitnet.ait.ac.th/" \
    -A "$UA" \
    --data "$data" -D "$hdr" "$LOGIN_URL" -o "$resp"
  rc=$?
  set -e
  [[ $rc -ne 0 ]] && log "[WARN] POST exited $rc. See $hdr / $resp (tmp)."

  dns_dhcp_refresh
  if has_full_internet; then
    log "[OK] Internet is open. Login succeeded."
    return 0
  fi

  # heuristic success
  if grep -qiE 'welcome|logout|signed in|dashboard' "$resp"; then
    log "[OK] Portal hints success; connectivity may take a moment."
    return 0
  fi
  log "[WARN] Login attempt may have failed."
  return 1
}

do_logout() {
  # logout page wants username/password again
  require_creds
  local wd cook hdr resp data rc
  wd="$(mktemp -d)"; cook="$wd/c.txt"; hdr="$wd/h.txt"; resp="$wd/r.html"
  trap 'rm -rf "$wd"' RETURN

  # Some portals require a fresh cookie before logout; fetch the site root
  curl -fsSL -c "$cook" -A "$UA" "$PORTAL_URL" -o /dev/null

  data="username=$(urlencode "$AIT_USER")&password=$(urlencode "$AIT_PASS")"
  log "[INFO] POST $LOGOUT_URL"
  set +e
  curl -fsS -b "$cook" -c "$cook" -L \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Origin: https://aitnet.ait.ac.th" \
    -H "Referer: https://aitnet.ait.ac.th/" \
    -A "$UA" \
    --data "$data" -D "$hdr" "$LOGOUT_URL" -o "$resp"
  rc=$?
  set -e
  [[ $rc -ne 0 ]] && log "[WARN] Logout POST exited $rc (continuing)."

  dns_dhcp_refresh
  if has_full_internet; then
    # Some portals keep you online even after posting logout (per-user vs per-MAC differences)
    log "[INFO] Still online after logout request (expected on some networks)."
    return 0
  fi
  log "[OK] Logout request sent."
  return 0
}

# ---------- retry wrapper ----------
retry_login_until_online() {
  local tries="${1:-3}" delay="${2:-3}" i
  for (( i=1; i<=tries; i++ )); do
    log "[INFO] Login attempt $i/$tries…"
    if do_login 1; then
      if has_full_internet; then
        log "[OK] Online after attempt $i."
        return 0
      fi
    fi
    [[ $i -lt $tries ]] && { log "[INFO] Sleeping ${delay}s before retry…"; sleep "$delay"; }
  done
  log "[ERROR] Still not online after $tries attempts."
  return 1
}

# ---------- CLI ----------
cmd="${1:-login}"
case "$cmd" in
  login)
    shift || true
    if [[ "${1:-}" == "--force" || "${1:-}" == "-f" ]]; then do_login 1; else do_login 0; fi
    ;;
  logout)
    do_logout
    ;;
  relogin)
    log "[INFO] Re-login: sending logout then login…"
    do_logout || true
    retry_login_until_online 3 3
    ;;
  status)
    show_status
    ;;
  *)
    echo "Usage: $0 {login [--force]|logout|relogin|status}"
    exit 2
    ;;
esac
