#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(basename "$SCRIPT_DIR")" == "systemd" ]]; then
  cd "$SCRIPT_DIR/.."
fi

RES_PATH="./systemd"

# -----------------------------
# Defaults
# -----------------------------

UPSTREAMS="169.254.169.253:53"
MAX_REQUESTS="10000"
RATE_WINDOW="1"
MAX_CACHE_TTL="3600"
MAX_CACHE_ENTRIES="200000"

FORCE="false"
DRY_RUN="false"

SERVICE_NAME="dnscache"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_DIR="/etc/dnscache"
ENV_FILE="${ENV_DIR}/dnscache.env"
BINARY_SRC="./dnscache"
BINARY_DST="/usr/local/bin/dnscache"

# -----------------------------
# Helper functions
# -----------------------------

error() {
  echo "[ERROR] $1"
  exit 1
}

info() {
  echo "[*] $1"
}

is_positive_integer() {
  [[ "$1" =~ ^[0-9]+$ ]] && [[ "$1" -gt 0 ]]
}

validate_upstreams() {
  IFS=',' read -ra ADDR <<< "$1"
  for entry in "${ADDR[@]}"; do
    if ! [[ "$entry" =~ ^[0-9a-zA-Z\.\-:]+:[0-9]+$ ]]; then
      error "Invalid upstream format: $entry (expected host:port)"
    fi
  done
}

run_cmd() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[DRY-RUN] $*"
  else
    eval "$@"
  fi
}

# -----------------------------
# Parse CLI arguments
# -----------------------------

PARSED=$(getopt --options "" \
  --longoptions upstreams:,max-requests:,rate-window:,max-cache-ttl:,max-cache-entries:,force,dry-run \
  --name "$0" -- "$@") || exit 2

eval set -- "$PARSED"

while true; do
  case "$1" in
    --upstreams)
      UPSTREAMS="$2"
      shift 2
      ;;
    --max-requests)
      MAX_REQUESTS="$2"
      shift 2
      ;;
    --rate-window)
      RATE_WINDOW="$2"
      shift 2
      ;;
    --max-cache-ttl)
      MAX_CACHE_TTL="$2"
      shift 2
      ;;
    --max-cache-entries)
      MAX_CACHE_ENTRIES="$2"
      shift 2
      ;;
    --force)
      FORCE="true"
      shift
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    --)
      shift
      break
      ;;
    *)
      error "Unknown option: $1"
      ;;
  esac
done

# -----------------------------
# Validate inputs
# -----------------------------

validate_upstreams "$UPSTREAMS"

is_positive_integer "$MAX_REQUESTS" || error "MAX_REQUESTS must be a positive integer"
is_positive_integer "$RATE_WINDOW" || error "RATE_WINDOW must be a positive integer"
is_positive_integer "$MAX_CACHE_TTL" || error "MAX_CACHE_TTL must be a positive integer"
is_positive_integer "$MAX_CACHE_ENTRIES" || error "MAX_CACHE_ENTRIES must be a positive integer"

# -----------------------------
# Root check
# -----------------------------

if [[ "$DRY_RUN" != "true" ]] && [[ $EUID -ne 0 ]]; then
  error "Please run as root"
fi

info "Installing dnscache with configuration:"
echo "  UPSTREAMS=$UPSTREAMS"
echo "  MAX_REQUESTS=$MAX_REQUESTS"
echo "  RATE_WINDOW=$RATE_WINDOW"
echo "  MAX_CACHE_TTL=$MAX_CACHE_TTL"
echo "  MAX_CACHE_ENTRIES=$MAX_CACHE_ENTRIES"
echo "  FORCE=$FORCE"
echo "  DRY_RUN=$DRY_RUN"

# -----------------------------
# Install binary
# -----------------------------

[[ -f "$BINARY_SRC" ]] || error "Binary not found at $BINARY_SRC"

run_cmd "install -m 0755 \"$BINARY_SRC\" \"$BINARY_DST\""

# -----------------------------
# Create user/group
# -----------------------------

if ! id -u dnscache >/dev/null 2>&1; then
  run_cmd "useradd --system --no-create-home --shell /usr/sbin/nologin dnscache"
fi

if ! getent group dnscache >/dev/null 2>&1; then
  run_cmd "groupadd --system dnscache"
fi

# -----------------------------
# Create config directory
# -----------------------------

run_cmd "mkdir -p \"$ENV_DIR\""
run_cmd "chown root:dnscache \"$ENV_DIR\""
run_cmd "chmod 750 \"$ENV_DIR\""

# -----------------------------
# Generate ENV file
# -----------------------------

if [[ -f "$ENV_FILE" && "$FORCE" != "true" ]]; then
  info "Environment file exists. Use --force to overwrite."
else
  info "Writing environment file to $ENV_FILE"

  if [[ "$DRY_RUN" == "true" ]]; then
    cat <<EOF
DNSCACHE_UPSTREAMS=$UPSTREAMS
DNSCACHE_MAX_REQUESTS=$MAX_REQUESTS
DNSCACHE_RATE_LIMIT_WINDOW_SECS=$RATE_WINDOW
DNSCACHE_MAX_CACHE_TTL_SECS=$MAX_CACHE_TTL
DNSCACHE_MAX_CACHE_ENTRIES=$MAX_CACHE_ENTRIES
EOF
  else
    cat <<EOF > "$ENV_FILE"
# dnscache configuration

DNSCACHE_UPSTREAMS=$UPSTREAMS
DNSCACHE_MAX_REQUESTS=$MAX_REQUESTS
DNSCACHE_RATE_LIMIT_WINDOW_SECS=$RATE_WINDOW
DNSCACHE_MAX_CACHE_TTL_SECS=$MAX_CACHE_TTL
DNSCACHE_MAX_CACHE_ENTRIES=$MAX_CACHE_ENTRIES
EOF

    chown root:dnscache "$ENV_FILE"
    chmod 640 "$ENV_FILE"
  fi
fi

# -----------------------------
# Install systemd service
# -----------------------------

if [[ -f "${RES_PATH}/dnscache.service" ]]; then
  run_cmd "install -m 0644 ${RES_PATH}/dnscache.service \"$SERVICE_FILE\""
fi

run_cmd "systemctl daemon-reload"
run_cmd "systemctl enable $SERVICE_NAME"

echo
info "dnscache installation complete."
echo

if [[ "$DRY_RUN" == "true" ]]; then
  echo "This was a dry run. No changes were made."
else
  echo "IMPORTANT:"
  echo "If systemd-resolved is running on port 53,"
  echo "disable the stub listener before starting dnscache:"
  echo
  echo "  Edit /etc/systemd/resolved.conf"
  echo "  Set: DNSStubListener=no"
  echo "  systemctl restart systemd-resolved"
  echo
  echo "Then run:"
  echo "  systemctl start dnscache"
fi
