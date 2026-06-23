#!/usr/bin/env bash
#
# macOS bootstrap for headless Ghidra farm:
# - Install JDK 21 (required for Ghidra 11.4.x)
# - Install Python 3.12 + uv
# - Optionally install Ghidra from a local zip, version/date, or URL
#
# This script is intentionally strict and idempotent-ish.
#
# References:
# - Ghidra 11.4 "What's New" (JDK 21 requirement):
#   https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_11.4.2_build/Ghidra/Configurations/Public_Release/src/global/docs/WhatsNew.md
#
set -euo pipefail

red() { printf "\033[0;31m%s\033[0m\n" "$*"; }
grn() { printf "\033[0;32m%s\033[0m\n" "$*"; }
ylw() { printf "\033[1;33m%s\033[0m\n" "$*"; }
blu() { printf "\033[0;34m%s\033[0m\n" "$*"; }

die() { red "error: $*"; exit 1; }

DEFAULT_GHIDRA_VERSION="11.4.2"
DEFAULT_GHIDRA_DATE="20250826"

ghidra_release_url() {
  local version="$1"
  local date="$2"
  printf "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_%s_build/ghidra_%s_PUBLIC_%s.zip" \
    "$version" "$version" "$date"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

ensure_line_in_file() {
  local file="$1"
  local line="$2"
  mkdir -p "$(dirname "$file")" || true
  touch "$file"
  if ! /usr/bin/grep -F -q -- "$line" "$file"; then
    printf "\n%s\n" "$line" >>"$file"
  fi
}

is_macos() {
  [[ "$(uname -s)" == "Darwin" ]]
}

install_homebrew_if_requested() {
  local want="$1"
  if command -v brew >/dev/null 2>&1; then
    return 0
  fi
  if [[ "$want" != "1" ]]; then
    die "Homebrew is not installed. Re-run with --install-brew, or install from https://brew.sh/"
  fi
  ylw "Installing Homebrew (interactive; may prompt)..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
}

brew_install_if_missing() {
  local formula="$1"
  if brew list --formula "$formula" >/dev/null 2>&1; then
    return 0
  fi
  ylw "brew install $formula"
  brew install "$formula"
}

maybe_symlink_jdk() {
  # Many wrappers use /Library/Java/JavaVirtualMachines; Homebrew recommends this symlink.
  local src="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk"
  local dst="/Library/Java/JavaVirtualMachines/openjdk-21.jdk"
  if [[ -d "$dst" ]]; then
    return 0
  fi
  if [[ ! -d "$src" ]]; then
    ylw "openjdk@21 installed but expected JDK bundle missing at $src (continuing)"
    return 0
  fi
  ylw "Creating system JDK symlink (sudo may prompt)"
  sudo ln -sfn "$src" "$dst"
}

install_ghidra_from_zip() {
  local zip_path="$1"
  local dest_dir="$2"
  local version="$3"

  [[ -f "$zip_path" ]] || die "ghidra zip not found: $zip_path"
  mkdir -p "$dest_dir"

  # Unzip produces a versioned folder name; put it under dest_dir and then normalize.
  ylw "Unzipping Ghidra into $dest_dir"
  /usr/bin/unzip -q -o "$zip_path" -d "$dest_dir"

  # Find the extracted ghidra_*_PUBLIC* directory.
  local extracted
  extracted="$(/bin/ls -1 "$dest_dir" | /usr/bin/grep -E "^ghidra_${version//./\\.}_.*PUBLIC" | /usr/bin/head -1 || true)"
  if [[ -z "$extracted" ]]; then
    extracted="$(/bin/ls -1 "$dest_dir" | /usr/bin/grep -E '^ghidra_.*PUBLIC' | /usr/bin/head -1 || true)"
  fi
  [[ -n "$extracted" ]] || die "could not locate extracted ghidra_*_PUBLIC directory under $dest_dir"

  local extracted_path="$dest_dir/$extracted"
  local normalized="$dest_dir/ghidra_${version}_PUBLIC"
  if [[ "$extracted_path" != "$normalized" ]]; then
    ylw "Normalizing install dir to $normalized"
    /bin/rm -rf "$normalized"
    /bin/mv "$extracted_path" "$normalized"
  fi

  # Clear quarantine.
  if command -v xattr >/dev/null 2>&1; then
    ylw "Clearing Gatekeeper quarantine"
    xattr -dr com.apple.quarantine "$normalized" || true
  fi

  [[ -x "$normalized/support/analyzeHeadless" ]] || die "Ghidra install missing support/analyzeHeadless at $normalized"
  grn "Ghidra installed at: $normalized"
}

download_to() {
  local url="$1"
  local out="$2"
  require_cmd curl
  ylw "Downloading: $url"
  curl -fL --retry 3 --retry-delay 1 -o "$out" "$url"
}

usage() {
  cat <<'EOF'
Usage: scripts/setup_mac.sh [options]

Options:
  --install-brew              Install Homebrew if missing
  --zshrc PATH                Zsh rc file to edit (default: ~/.zshrc)

  --with-ghidra               Also install/configure Ghidra
  --ghidra-version VERSION    Ghidra version to install (default: 11.4.2)
  --ghidra-date YYYYMMDD      Release asset date (default: 20250826 for 11.4.2)
  --ghidra-zip PATH           Local path to a Ghidra PUBLIC zip
  --ghidra-url URL            URL to download a Ghidra PUBLIC zip (overrides version/date URL)
  --ghidra-dest-dir PATH      Destination directory to unzip into (default: ~/tools)

Examples:
  # Install JDK21 + Python3.12 + uv only:
  scripts/setup_mac.sh --install-brew

  # Install everything (Ghidra zip already downloaded):
  scripts/setup_mac.sh --install-brew --with-ghidra --ghidra-zip ~/Downloads/ghidra_11.4.2_PUBLIC_*.zip

  # Install a specific release asset:
  scripts/setup_mac.sh --install-brew --with-ghidra --ghidra-version 11.4.2 --ghidra-date 20250826

  # Install from an explicit URL:
  scripts/setup_mac.sh --install-brew --with-ghidra --ghidra-url 'https://...' --ghidra-dest-dir ~/tools

  # Install everything (use default Ghidra URL):
  scripts/setup_mac.sh --install-brew --with-ghidra --ghidra-dest-dir ~/tools
EOF
}

main() {
  is_macos || die "this script is for macOS only"

  local install_brew=0
  local with_ghidra=0
  local zshrc="${HOME}/.zshrc"
  local ghidra_zip=""
  local ghidra_url=""
  local ghidra_version="$DEFAULT_GHIDRA_VERSION"
  local ghidra_date="$DEFAULT_GHIDRA_DATE"
  local ghidra_dest_dir="${HOME}/tools"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --install-brew) install_brew=1; shift ;;
      --with-ghidra) with_ghidra=1; shift ;;
      --zshrc) zshrc="$2"; shift 2 ;;
      --ghidra-version) ghidra_version="$2"; shift 2 ;;
      --ghidra-date) ghidra_date="$2"; shift 2 ;;
      --ghidra-zip) ghidra_zip="$2"; shift 2 ;;
      --ghidra-url) ghidra_url="$2"; shift 2 ;;
      --ghidra-dest-dir) ghidra_dest_dir="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1" ;;
    esac
  done

  blu "== Homebrew =="
  install_homebrew_if_requested "$install_brew"
  require_cmd brew

  blu "== Install packages =="
  brew_install_if_missing "openjdk@21"
  brew_install_if_missing "python@3.12"
  brew_install_if_missing "uv"

  blu "== Wire PATH (zsh) =="
  # Prefer brew-managed shims so `python3` points to the selected formula.
  ensure_line_in_file "$zshrc" 'export PATH="/opt/homebrew/opt/openjdk@21/bin:$PATH"'
  ensure_line_in_file "$zshrc" 'export PATH="/opt/homebrew/opt/python@3.12/libexec/bin:$PATH"'
  ensure_line_in_file "$zshrc" 'export PATH="/opt/homebrew/bin:$PATH"'

  blu "== System Java symlink (optional but recommended) =="
  maybe_symlink_jdk

  blu "== Verify versions =="
  # Use absolute paths where feasible to avoid PATH confusion before the user reloads shell.
  /opt/homebrew/opt/openjdk@21/bin/java -version
  /opt/homebrew/bin/python3.12 --version
  if command -v uv >/dev/null 2>&1; then
    uv --version
  else
    ylw "uv not on PATH yet; open a new shell or source your zshrc"
  fi

  if [[ "$with_ghidra" == "1" ]]; then
    blu "== Ghidra ${ghidra_version} =="
    if [[ -n "$ghidra_zip" && -n "$ghidra_url" ]]; then
      die "choose only one: --ghidra-zip or --ghidra-url"
    fi
    if [[ -z "$ghidra_zip" && -z "$ghidra_url" ]]; then
      ghidra_url="$(ghidra_release_url "$ghidra_version" "$ghidra_date")"
      ylw "No --ghidra-zip/--ghidra-url provided; using version/date URL:"
      ylw "  $ghidra_url"
    fi

    local tmp_zip=""
    if [[ -n "$ghidra_url" ]]; then
      tmp_zip="$(mktemp -t "ghidra_${ghidra_version}.XXXXXX.zip")"
      download_to "$ghidra_url" "$tmp_zip"
      ghidra_zip="$tmp_zip"
    fi

    install_ghidra_from_zip "$ghidra_zip" "$ghidra_dest_dir" "$ghidra_version"

    if [[ -n "$tmp_zip" ]]; then
      /bin/rm -f "$tmp_zip"
    fi
  fi

  grn "Done."
  ylw "Next step: open a new shell or run: source \"$zshrc\""
}

main "$@"
