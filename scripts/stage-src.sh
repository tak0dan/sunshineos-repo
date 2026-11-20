#!/usr/bin/env bash
# Turns a SunshineOS checkout into the source tarballs of sunshine-base and sunshine-payload (one tree per package, laid out
# like the installed files). Scripts that the ISO keeps in /usr/local/bin are installed to /usr/bin, and their references are rewritten.
# usage: scripts/stage-src.sh /path/to/SunshineOS      (the payload needs a finished tools/import-end4.sh run in that checkout)
set -euo pipefail
SRC=${1:?path to the SunshineOS checkout}
HERE=$(cd "$(dirname "$0")/.." && pwd)
A=$SRC/profile/airootfs
# File modes are normalised (dirs 755, files 644, or 755 when the owner can execute), owner root: a checkout made with a restrictive
# umask or ACL (770/660) must never reach another machine, where rsync/pacman would apply it to system directories.
normalise() { find "$1" -type d -exec chmod u=rwx,go=rx,g-s {} +; find "$1" -type f -perm -u+x -exec chmod 755 {} +; find "$1" -type f ! -perm -u+x -exec chmod 644 {} +; }
pack() { tar --zstd --owner=0 --group=0 --numeric-owner -C "$1" -cf "$2" .; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

# ---- sunshine-base
B=$T/base; mkdir -p "$B/usr/bin" "$B/usr/share" "$B/usr/lib/systemd/user" "$B/etc/grub.d"
for s in doctor identity info update-notifier update-run toolbox welcome pet pods term prompt session session-notice set-shell \
         snapshot snapshots-setup cleanup boot-repair fix-pacman fastfetch-patch hyprland-install plasma-setup nixos-grub crypt-setup repo apps webapp topbar update-check rescue kernel performance gaming drivers desktops toolsync migrate pacnew reset-plasma fix support backup state-hook health-scan game-run secureboot diagnose restore-visuals theme-wallpapers windfall-default; do
  [ -f "$A/usr/local/bin/sunshine-$s" ] && install -m755 "$A/usr/local/bin/sunshine-$s" "$B/usr/bin/sunshine-$s" || echo "note: sunshine-$s not in the checkout"
done
cp -a "$A"/usr/bin/sunshine-store* "$B/usr/bin/"
cp -a "$A/usr/lib/sunshine-store" "$B/usr/lib/"
cp -a "$A"/usr/lib/systemd/user/sunshine-store-indexer.* "$B/usr/lib/systemd/user/"
mkdir -p "$B/usr/lib/systemd/system" "$B/etc/sunshine"; cp -a "$A"/usr/lib/systemd/system/sunshine-*.service "$A"/usr/lib/systemd/system/sunshine-*.timer "$B/usr/lib/systemd/system/" 2>/dev/null; cp -a "$A"/etc/sunshine/snapshots.conf "$B/etc/sunshine/"
cp -a "$A"/etc/systemd/user/sunshine-update-notifier.* "$B/usr/lib/systemd/user/"
cp -a "$A"/usr/lib/systemd/user/sunshine-diagnose.* "$B/usr/lib/systemd/user/" 2>/dev/null || true
mkdir -p "$B/usr/lib/sunshine" "$B/usr/share/plasma/plasmoids"; cp -a "$A/usr/local/lib/sunshine/ui.sh" "$B/usr/lib/sunshine/"; cp -a "$A"/usr/share/plasma/plasmoids/com.sunshineos.* "$B/usr/share/plasma/plasmoids/" 2>/dev/null || true
cp -a "$A/etc/sunshine/tools.conf" "$A/etc/sunshine/repos.conf" "$B/etc/sunshine/" 2>/dev/null || true
mkdir -p "$B/usr/share/pacman/keyrings"; cp -a "$A"/usr/share/pacman/keyrings/sunshine.* "$B/usr/share/pacman/keyrings/"
install -m755 "$A/etc/grub.d/42_nixos" "$B/etc/grub.d/42_nixos"
for d in libalpm aurorae color-schemes icons pixmaps plasma sddm sunshine-store wallpapers; do cp -a "$A/usr/share/$d" "$B/usr/share/"; done
mkdir -p "$B/usr/share/applications" "$B/usr/share/grub"
cp -a "$A"/usr/share/applications/sunshine-*.desktop "$B/usr/share/applications/"; rm -f "$B/usr/share/applications/sunshine-install.desktop" "$B/usr/share/applications/sunshine-update.desktop"
cp -a "$A/usr/share/grub/themes" "$B/usr/share/grub/"
rsync -a --exclude=/hyprland --exclude=/pkgs "$A/usr/share/sunshine/" "$B/usr/share/sunshine/"   # includes apps-setup/, catalogue.toml
mkdir -p "$B/usr/share/sunshine/package-lists"; cp "$HERE"/package-list/*.txt "$B/usr/share/sunshine/package-lists/"
install -m755 "$HERE"/overlay/usr/bin/sunshine-converge "$HERE"/overlay/usr/bin/sunshine-payload-apply "$B/usr/bin/"
# the live-only pieces of the hook directory: none today; the rest refers to /usr/local/bin/sunshine-*
grep -rlI '/usr/local/lib/sunshine/' "$B" 2>/dev/null | xargs -r sed -i 's#/usr/local/lib/sunshine/#/usr/lib/sunshine/#g'
grep -rlI '/usr/local/bin/sunshine-' "$B" 2>/dev/null | xargs -r sed -i 's#/usr/local/bin/sunshine-#/usr/bin/sunshine-#g'
# every pacman hook, systemd unit and menu entry in the package must run a Sunshine program that is in the package too: a tool that is
# missing from the list above leaves a hook that fails on every update ("call to execv failed") and is only noticed on installed systems
missing=$(grep -rhoE '^(Exec|ExecStart|ExecStartPre|ExecStartPost|ExecStop)[[:space:]]*=[[:space:]]*[-@!+:]*/usr/(bin|lib)/sunshine[^[:space:]]*' \
            "$B/usr/share/libalpm/hooks" "$B/usr/lib/systemd" "$B/usr/share/applications" 2>/dev/null \
          | sed -E 's/^[^=]*=[[:space:]]*[-@!+:]*//; s/[;"]+$//' | sort -u | while read -r p; do [ -e "$B$p" ] || echo "$p"; done)
[ -z "$missing" ] || { echo "sunshine-base: referenced but not packaged (add them to the tool list):" $missing >&2; exit 1; }
normalise "$B"; pack "$B" "$HERE/packages/sunshine-base/sunshine-base-src.tar.zst"
echo "sunshine-base source: $(du -h "$HERE/packages/sunshine-base/sunshine-base-src.tar.zst" | cut -f1)"

# ---- sunshine-update: the dedicated update command and the Evolution Engine
# The wrapper and the engine sources live in this repo; sunshine-base keeps the update-run helper and notifier.
U=$T/update; mkdir -p "$U/usr/bin" "$U/usr/lib/sunshine/evolution-engine" "$U/usr/share/applications"
install -m755 "$HERE/packages/sunshine-update/sunshine-update" "$U/usr/bin/sunshine-update"
cp -a "$HERE/packages/sunshine-update/engine/." "$U/usr/lib/sunshine/evolution-engine/"
cp -a "$HERE/packages/sunshine-update/sunshine-update.desktop" "$U/usr/share/applications/"
normalise "$U"; pack "$U" "$HERE/packages/sunshine-update/sunshine-update-src.tar.zst"
echo "sunshine-update source: $(du -h "$HERE/packages/sunshine-update/sunshine-update-src.tar.zst" | cut -f1)"

# ---- sunshine-payload: the Hyprland dots, Python venv, session files (applied by sunshine-doctor / sunshine-payload-apply)
P=$A/usr/share/sunshine/hyprland
if [ -d "$P/root" ]; then
  mkdir -p "$T/pay/usr/share/sunshine/hyprland"; cp -a "$P/root" "$P/packages.txt" "$T/pay/usr/share/sunshine/hyprland/"
  normalise "$T/pay"; pack "$T/pay" "$HERE/packages/sunshine-payload/sunshine-payload-src.tar.zst"
  echo "sunshine-payload source: $(du -h "$HERE/packages/sunshine-payload/sunshine-payload-src.tar.zst" | cut -f1)"
else echo "no Hyprland payload in the checkout (run tools/import-end4.sh); sunshine-payload not staged"; fi
