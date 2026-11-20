"""Reusable, offline fixture roots and command executors.

The engine normally inspects the live machine.  For review, tests and demos it
can instead use a fixture root plus an injected executor.  Keeping the executor
here (rather than in the test suite) means the CLI can run ``--check`` and
``--plan`` against the exact same simulated machine as the unit tests, without
leaking host state through ``subprocess.run``.

Fixture executors are deliberately conservative: unknown commands fail, just as
they would on a machine where a tool is not installed.  They never mutate the
host.
"""
from __future__ import annotations

import json
import shlex
import shutil
from pathlib import Path
from typing import Callable, Iterable

Execute = Callable[[str], tuple[int, str, str]]

FIXTURES_ROOT = Path(__file__).resolve().parent.parent / "fixtures"
FIXTURE_NAMES = (
    "clean-arch",
    "arch-plasma",
    "arch-hyprland",
    "arch-gnome",
    "arch-xfce",
    "arch-sway",
    "arch-five-year-old",
    "arch-ext4-luks-systemd-boot",
    "arch-btrfs-grub-nvidia-aur",
    "old-sunshine",
)

_BASE_PACKAGES = (
    "base 1.1-1\n"
    "systemd 255.8-1\n"
    "pacman 7.1.0-1\n"
    "dbus 1.16.0-1\n"
    "sudo 1.9.16-1\n"
    "linux 6.10.1-arch1-1\n"
    "linux-headers 6.10.1-arch1-1\n"
    "linux-firmware 2026.08-1\n"
    "mkinitcpio 39-1\n"
    "grub 2.12-1\n"
    "efibootmgr 18-1\n"
    "os-prober 1.82-1\n"
    "rsync 3.3.0-1\n"
    "btrfs-progs 6.10.1-1\n"
    "networkmanager 1.48-1\n"
    "pipewire 1.2.0-1\n"
    "wireplumber 0.5.0-1\n"
)

_DESKTOP_PACKAGES = {
    "arch-plasma": "plasma-desktop 6.1.0-1\nsddm 0.21.0-1\n",
    "arch-hyprland": "hyprland 0.42.0-1\n",
    "arch-gnome": "gnome-shell 47.0-1\ngdm 47.0-1\n",
    "arch-xfce": "xfce4 4.20-1\nlightdm 1.32-1\n",
    "arch-sway": "sway 1.10-1\n",
}

# Source-matrix axes (spec G5).  Each profile changes only the signals that
# matter for its axis; everything else uses the same discovery/planning code.
# ``foreign`` is the output of ``pacman -Qqm`` (names only), and ``removed``
# packages are dropped from the base inventory.
_FIXTURE_PROFILES: dict[str, dict[str, object]] = {
    "arch-ext4-luks-systemd-boot": {
        "add_packages": ("systemd-boot 255.8-1", "cryptsetup 2.7.4-1"),
        "removed": ("grub", "os-prober", "btrfs-progs"),
        "foreign": (),
        "lsblk": (
            '{"blockdevices":[{"name":"nvme0n1","type":"disk","children":['
            '{"name":"nvme0n1p1","type":"part","fstype":"vfat","mountpoint":"/boot"},'
            '{"name":"nvme0n1p2","type":"part","fstype":"crypto_LUKS","mountpoint":null},'
            '{"name":"cryptroot","type":"crypt","fstype":"ext4","mountpoint":"/"}]}]}'
        ),
        "findmnt": (
            "/ /dev/mapper/cryptroot ext4\n"
            "/boot /dev/nvme0n1p1 vfat\n"
            "/sys/firmware/efi/efivars efivarfs\n"
        ),
        "btrfs": False,
        "efi_entries": ("Boot0001* Linux Boot Manager HD(1,GPT)/File(\\EFI\\SYSTEMD\\SYSTEMD-BOOTX64.EFI)",),
    },
    "arch-btrfs-grub-nvidia-aur": {
        "add_packages": (
            "nvidia 560.35.03-1",
            "nvidia-utils 560.35.03-1",
            "dkms 3.0.12-1",
            "yay 12.3.5-1",
        ),
        "removed": (),
        "foreign": ("yay", "nvidia-dkms", "sunshine-theme-rose-pine"),
        "lsblk": (
            '{"blockdevices":[{"name":"nvme0n1","type":"disk","children":['
            '{"name":"nvme0n1p1","type":"part","fstype":"vfat","mountpoint":"/boot"},'
            '{"name":"nvme0n1p2","type":"part","fstype":"btrfs","mountpoint":"/"}]}]}'
        ),
        "findmnt": (
            "/ /dev/nvme0n1p2 btrfs\n"
            "/home /dev/nvme0n1p2 btrfs\n"
            "/boot /dev/nvme0n1p1 vfat\n"
            "/sys/firmware/efi/efivars efivarfs\n"
        ),
        "btrfs": True,
        "efi_entries": ("Boot0002* GRUB HD(1,GPT)/File(\\EFI\\arch\\grubx64.efi)",),
    },
}


def fixture_root(name: str) -> Path:
    """Return the filesystem tree for *name*, rejecting path traversal."""
    if name not in FIXTURE_NAMES:
        raise ValueError(
            f"unknown fixture '{name}'; available: " + ", ".join(FIXTURE_NAMES)
        )
    root = FIXTURES_ROOT / name
    if not root.is_dir():
        raise FileNotFoundError(f"fixture directory is missing: {root}")
    return root


class FixtureExecutor:
    """Offline command executor matching the simulated fixture roots.

    ``state_root`` is the *sandbox* the caller chose for a real (non-dry-run)
    fixture apply.  Effects such as generated initramfs images are created only
    there, never under the fixture source tree or the host root.
    """

    def __init__(self, name: str, state_root: str | Path | None = None):
        self.name = name
        self.state_root = Path(state_root) if state_root is not None else None
        self.commands: list[str] = []
        self.fail_on: list[tuple[str, str]] = []
        self.profile = dict(_FIXTURE_PROFILES.get(name, {}))
        packages = _BASE_PACKAGES + _DESKTOP_PACKAGES.get(name, "")
        packages += "".join(
            str(line) + "\n" for line in self.profile.get("add_packages", ())
        )
        if name == "old-sunshine":
            packages += "sunshine-agent 0.9.1-1\nsunshine-config 2026.1-1\n"
        removed = set(self.profile.get("removed", ()))  # type: ignore[arg-type]
        self.package_lines: dict[str, str] = {
            line.split()[0]: line.strip()
            for line in packages.splitlines()
            if line.strip() and line.split()[0] not in removed
        }
        self.packages: set[str] = set(self.package_lines)
        self.foreign: set[str] = set(self.profile.get("foreign", ()))  # type: ignore[arg-type]
        self.boot_entries: set[str] = set()
        self.state_file = (
            self.state_root / "migration" / "fixture-state.json"
            if self.state_root is not None else None
        )
        if self.state_file is not None and self.state_file.is_file():
            try:
                saved = json.loads(self.state_file.read_text(encoding="utf-8"))
                self.packages = set(saved.get("packages", self.packages))
                self.foreign = set(saved.get("foreign", self.foreign))
                self.boot_entries = set(saved.get("boot_entries", set()))
            except (OSError, json.JSONDecodeError):
                pass
        # A migrated sandbox already carries its own filesystem. Re-seeding it
        # here would hide tampering with validated kernel/session directories.
        fresh_sandbox = self.state_root is not None and not (
            self.state_file is not None and self.state_file.exists()
        )
        if fresh_sandbox:
            (self.state_root / "usr/lib/modules/6.10.1-arch1-1").mkdir(
                parents=True, exist_ok=True
            )
            session = self.state_root / "usr/share/wayland-sessions"
            # Fixtures without a detected desktop still accept the standard
            # --decide desktop-profile=hyprland used by the CI matrix. Without
            # a session file the post-apply validator correctly fails.
            decided_hyprland = name in {
                "clean-arch", "arch-five-year-old",
                "arch-ext4-luks-systemd-boot", "arch-btrfs-grub-nvidia-aur",
            }
            if decided_hyprland or name in _DESKTOP_PACKAGES or name == "old-sunshine":
                session.mkdir(parents=True, exist_ok=True)
                session_name = "hyprland" if decided_hyprland else name.replace("arch-", "")
                (session / f"{session_name}.desktop").write_text(
                    "[Desktop Entry]\nName=Fixture session\n", encoding="utf-8"
                )

    def fail(self, needle: str, error: str = "injected fixture failure") -> None:
        """Make the next commands containing *needle* fail, for break tests."""
        self.fail_on.append((needle, error))

    def tampered(self, name: str) -> bool:
        """Whether a post-migration tamper marker is present in the sandbox.

        Markers live at ``<state_root>/migration/tamper/<name>``. They let CLI
        ``--verify`` tamper tests break command-backed capabilities without
        changing the fixture source or the host machine.
        """
        return (
            self.state_root is not None
            and (self.state_root / "migration" / "tamper" / name).exists()
        )

    def _save(self) -> None:
        """Persist simulated package/boot state inside the caller's sandbox."""
        if self.state_file is None:
            return
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps({
            "packages": sorted(self.packages),
            "foreign": sorted(self.foreign),
            "boot_entries": sorted(self.boot_entries),
        }, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def __call__(self, command: str) -> tuple[int, str, str]:
        cmd = command.strip()
        self.commands.append(cmd)
        for needle, error in self.fail_on:
            if needle in cmd:
                return 1, "", error
        result = self._response(cmd)
        if result is None:
            return 1, "", f"command not available in fixture: {cmd}"
        return result

    def _response(self, cmd: str) -> tuple[int, str, str] | None:
        if cmd == "cat /proc/1/comm":
            return 0, "systemd\n", ""
        if cmd.startswith("systemctl --version"):
            return 0, "systemd 255 (255.8-1-arch)\n", ""
        if cmd.startswith("systemctl is-system-running"):
            if self.tampered("systemd"):
                return 1, "", "systemd manager is not running"
            return 0, "running\n", ""
        if cmd.startswith("systemctl is-enabled"):
            return 0, "enabled\n", ""
        if cmd.startswith("systemctl --user is-active") or cmd.startswith("systemctl is-active"):
            if self.tampered("audio") and "pipewire" in cmd:
                return 1, "", "inactive"
            return 0, "active\n", ""
        if cmd.startswith("systemctl enable "):
            return 0, f"Created symlink for {cmd.split()[-1]}\n", ""
        if cmd.startswith("systemctl disable "):
            return 0, f"Removed symlink for {cmd.split()[-1]}\n", ""
        if cmd.startswith("systemctl list-unit-files"):
            units = [
                "NetworkManager.service enabled",
                "pipewire.service enabled",
                "systemd-resolved.service enabled",
            ]
            if self.name == "arch-plasma":
                units.append("sddm.service enabled")
            return 0, "\n".join(units) + "\n", ""
        if cmd.startswith("systemctl list-units"):
            units = [
                "NetworkManager.service running",
                "pipewire.service running",
            ]
            if self.name == "arch-plasma":
                units.append("sddm.service running")
            return 0, "\n".join(units) + "\n", ""
        if cmd == "uname -m":
            return 0, "x86_64\n", ""
        if cmd.startswith("uname"):
            return 0, "6.10.1-arch1-1\n", ""
        if cmd == "pacman --version":
            if self.tampered("pacman"):
                return 1, "", "pacman foundation is unavailable"
            return 0, "Pacman v7.1.0\n", ""
        if cmd == "pacman -Q":
            lines_out = []
            for name in sorted(self.packages):
                line = self.package_lines.get(name)
                if line is None:
                    line = f"{name} 1.0-1"
                    self.package_lines[name] = line
                lines_out.append(line)
            return 0, "\n".join(lines_out) + "\n", ""
        if cmd.startswith("pacman -Q "):
            package = cmd.split(" ", 2)[-1].strip().strip("'\"")
            if package in self.packages:
                return 0, "1.0-1\n", ""
            return 1, "", f"package '{package}' not found"
        if cmd == "pacman -Syu --noconfirm":
            return 0, ":: Synchronizing package databases...\n", ""
        if cmd.startswith("pacman -S --needed --noconfirm"):
            names = [name.strip("'\"") for name in cmd.split("--noconfirm", 1)[-1].split()]
            self.packages.update(names)
            for name in names:
                self.package_lines.setdefault(name, f"{name} 1.0-1")
                self.foreign.discard(name)  # an installed official package is no longer foreign
            self._save()
            return 0, "installing " + " ".join(names) + "\n", ""
        if cmd.startswith("pacman -Rs --noconfirm"):
            names = [name.strip("'\"") for name in cmd.split("--noconfirm", 1)[-1].split()]
            self.packages.difference_update(names)
            self._save()
            return 0, "removed " + " ".join(names) + "\n", ""
        if cmd.startswith("pacman -Qqdt"):
            return 0, "", ""
        if cmd.startswith("pacman -Qqm"):
            return 0, "".join(name + "\n" for name in sorted(self.foreign)), ""
        if cmd.startswith("mkinitcpio --version"):
            return 0, "mkinitcpio 39\n", ""
        if cmd.startswith("mkinitcpio "):
            if self.state_root is not None:
                parts = shlex.split(cmd)
                preset = parts[parts.index("-p") + 1] if "-p" in parts else "linux"
                if "-g" in parts:
                    # Never let a fixture write to the real /boot: strip the
                    # absolute prefix and keep every effect in the sandbox.
                    rel_image = Path(parts[parts.index("-g") + 1])
                    image = self.state_root / str(rel_image).lstrip("/")
                else:
                    image = self.state_root / "boot" / f"initramfs-{preset}.img"
                image.parent.mkdir(parents=True, exist_ok=True)
                image.write_bytes(b"fixture initramfs\n")
                fallback = image.with_name(f"initramfs-{preset}-fallback.img")
                fallback.write_bytes(b"fixture fallback initramfs\n")
            return 0, "Image generation complete.\n", ""
        if cmd.startswith("efibootmgr -c"):
            parts = shlex.split(cmd)
            label = parts[parts.index("-L") + 1] if "-L" in parts else "Sunshine"
            self.boot_entries.add(label)
            self._save()
            return 0, f"Boot0009 {label} created\n", ""
        if cmd.startswith("efibootmgr -v"):
            if self.tampered("boot"):
                return 1, "", "firmware boot management is unavailable"
            entries = ["BootCurrent: 0001", "Boot0001* UEFI: NVMe"]
            profile_entries = self.profile.get("efi_entries", (
                "Boot0002* GRUB HD(1,GPT)/File(\\EFI\\arch\\grubx64.efi)",
            ))
            entries.extend(str(entry) for entry in profile_entries)  # type: ignore[union-attr]
            entries += [f"Boot000{i}* {label}" for i, label in enumerate(
                sorted(self.boot_entries), 9)]
            return 0, "\n".join(entries) + "\n", ""
        if cmd.startswith("findmnt"):
            output = self.profile.get("findmnt") or (
                "/ /dev/nvme0n1p2 btrfs\n"
                "/boot /dev/nvme0n1p1 vfat\n"
                "/sys/firmware/efi/efivars efivarfs\n"
            )
            return 0, str(output), ""
        if cmd.startswith("lsblk"):
            output = self.profile.get("lsblk") or (
                '{"blockdevices":[{"name":"nvme0n1","type":"disk","children":['
                '{"name":"nvme0n1p1","type":"part","fstype":"vfat","mountpoint":"/boot"},'
                '{"name":"nvme0n1p2","type":"part","fstype":"btrfs","mountpoint":"/"}]}]}'
            )
            return 0, str(output), ""
        if cmd.startswith("btrfs subvolume"):
            if self.profile.get("btrfs", True):
                return 0, "ID 256 gen 12 top level 5 path @\n", ""
            return 127, "", "btrfs-progs not installed on this ext4 system"
        if cmd.startswith("lvs") or cmd.startswith("pvs"):
            return 127, "", "logical volume tools unavailable"
        if cmd.startswith("nmcli --version"):
            return 0, "nmcli tool, version 1.48.0\n", ""
        if cmd.startswith("nmcli -t general status"):
            if self.tampered("network"):
                return 1, "", "NetworkManager is disconnected"
            return 0, "NetworkManager:connected:full\n", ""
        if cmd.startswith("networkctl --version"):
            return 127, "", "networkctl unavailable"
        if cmd.startswith("pw-cli"):
            return 0, "object: 1\n", ""
        if cmd.startswith("pactl"):
            return 0, "Server String: unix:/run/user/1000/pipewire-0\n", ""
        if cmd.startswith("ls /boot/initramfs"):
            images = sorted(
                str(p) for p in (self.state_root / "boot").glob("initramfs-*-fallback.img")
            ) if self.state_root is not None else []
            return (0, "\n".join(images) + "\n", "") if images else (1, "", "no fallback image")
        if cmd.startswith("getent passwd"):
            return 0, "sunshine:x:1000:1000:Sunshine User:/home/sunshine:/bin/bash\n", ""
        if cmd.startswith("sunshine") or cmd.startswith("sunshinectl") or \
                cmd.startswith("evolution-engine"):
            # Do not make a fixture look like it has installed Sunshine tools
            # unless the filesystem fixture actually provides them.
            return 127, "", "Sunshine CLI not installed in this fixture"
        return None


def materialize_fixture(name: str, destination: str | Path) -> Path:
    """Copy a fixture source tree into a sandbox as the post-migration root.

    Files already present in *destination* are never overwritten: apply effects
    (configuration, journals, generated images) are newer than the source and
    must win. This gives ``--verify`` a real filesystem to probe instead of the
    pristine fixture tree.
    """
    source = fixture_root(name)
    target = Path(destination)
    target.mkdir(parents=True, exist_ok=True)
    for item in source.rglob("*"):
        rel = item.relative_to(source)
        dest = target / rel
        if item.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
        elif item.is_file() and not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, dest)
    return target


def write_apply_marker(name: str, state_root: str | Path) -> None:
    """Record which fixture a sandbox was migrated from, for later verifies."""
    root = materialize_fixture(name, state_root)
    marker = root / "migration" / "fixture-source.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({
        "fixture": name,
        "root": str(root),
        "purpose": "post-migration verification root",
    }, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def applied_fixture(state_root: str | Path, expected: str) -> bool:
    marker = Path(state_root) / "migration" / "fixture-source.json"
    if not marker.is_file():
        return False
    try:
        return json.loads(marker.read_text(encoding="utf-8")).get("fixture") == expected
    except (OSError, json.JSONDecodeError, AttributeError):
        return False


def fixture_executor(name: str, state_root: str | Path | None = None) -> FixtureExecutor:
    fixture_root(name)  # validate the name before returning an executor
    return FixtureExecutor(name, state_root)


def provide_fixture_executor(name: str, commands: Iterable[str] = ()) -> Execute:
    """Return an executor pre-loaded with *commands* (used by tests)."""
    ex = fixture_executor(name)
    for command in commands:
        ex(command)
    return ex


__all__ = [
    "FIXTURE_NAMES",
    "FIXTURES_ROOT",
    "FixtureExecutor",
    "applied_fixture",
    "fixture_executor",
    "fixture_root",
    "materialize_fixture",
    "provide_fixture_executor",
    "write_apply_marker",
]
