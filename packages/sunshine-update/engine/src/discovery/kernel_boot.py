"""Discover the running/installed kernel, initramfs configuration and boot chain.

Observations produced here:

``kernel.running``
    ``uname -r``.  ``RUNNING`` describes the active kernel; the version string
    itself is kept in evidence so it does not become a capability token.

``kernel.installed``
    Directories below ``/usr/lib/modules`` represent installed kernel
    versions.  Presence of ``modules.order`` inside a directory is a stronger
    signal than a bare directory name.

``boot.mkinitcpio``
    ``/etc/mkinitcpio.conf``, ``/etc/mkinitcpio.d/*.preset`` and the
    ``mkinitcpio`` CLI.  CONFIGURED means a config exists; INSTALLED means only
    the tool exists.

``boot.efi`` / ``boot.esp``
    ``/sys/firmware/efi`` proves EFI firmware mode.  The EFI System Partition
    is corroborated by ``findmnt`` *and* ``/etc/fstab`` (a single source still
    counts, but at MEDIUM confidence).

``boot.efibootmgr``
    Whether ``efibootmgr -v`` is usable -- required for direct boot-entry
    management.

``bootloader`` (plus ``bootloader.<name>``)
    Bootloader confidence follows strict evidence rules:

    * installed package **alone** -> at most ``MEDIUM`` (a GRUB package says
      nothing about which entry firmware actually starts);
    * config file only -> ``MEDIUM``;
    * observed EFI boot entry -> ``MEDIUM``;
    * observed EFI boot entry **plus** config -> ``HIGH`` and ``RUNNING``.

    This prevents a planner from rewriting firmware entries on the strength of
    a package listing alone.
"""
from __future__ import annotations

try:  # package import keeps a single ObservedState class identity
    from ..core import Confidence, ObservedState, Status
except ImportError:  # pragma: no cover - supports standalone scripts in src/
    from core import Confidence, ObservedState, Status

from ._util import (
    Execute,
    abbreviate,
    as_execute,
    command_ok,
    confidence_rank,
    find_files,
    first_line,
    is_dir,
    lines,
    list_dir,
    observe,
    parse_fstab,
    path_exists,
    read_file,
    run,
)


_BOOTLOADERS: tuple[dict[str, object], ...] = (
    {
        "name": "grub",
        "token": "grub",
        "packages": ("grub", "grub-efi-x86_64", "grub-efi-amd64"),
        "entry_tokens": ("grub",),
        "configs": (
            "/boot/grub/grub.cfg",
            "/boot/grub2/grub.cfg",
            "/efi/EFI/arch/grub.cfg",
            "/efi/EFI/ubuntu/grub.cfg",
        ),
    },
    {
        "name": "systemd-boot",
        "token": "systemd-boot",
        "packages": ("systemd-boot", "systemd-boot-pacman-hook"),
        "entry_tokens": ("linux boot manager", "systemd-boot"),
        "configs": (
            "/boot/loader/loader.conf",
            "/efi/loader/loader.conf",
        ),
    },
    {
        "name": "refind",
        "token": "refind",
        "packages": ("refind", "refind-efi"),
        "entry_tokens": ("refind",),
        "configs": (
            "/efi/EFI/refind/refind.conf",
            "/boot/EFI/refind/refind.conf",
            "/etc/refind.d/refind.conf",
        ),
    },
)


def _detect_running_kernel(state: ObservedState, execute: Execute) -> str:
    """Record ``uname -r`` and return the raw release string."""
    rc, stdout, stderr = run(execute, "uname -r")
    release = first_line(stdout) if command_ok(rc) else ""
    evidence = [f"uname -r: {release or '(no output)'}"]
    if not release and stderr.strip():
        evidence.append("stderr: " + stderr.strip()[:200])
    observe(
        state,
        "kernel.running",
        "running-kernel",
        Confidence.HIGH if release else Confidence.LOW,
        Status.RUNNING if release else Status.ABSENT,
        evidence,
    )
    return release


def _detect_installed_kernels(state: ObservedState, root: str) -> list[str]:
    """List kernel module directories below ``/usr/lib/modules``."""
    entries = [
        name
        for name in list_dir(root, "/usr/lib/modules")
        if name not in ("packages", "") and any(ch.isdigit() for ch in name)
    ]
    evidence = [f"/usr/lib/modules: {abbreviate(entries)}"]
    complete = [name for name in entries if path_exists(root, f"/usr/lib/modules/{name}/modules.order")]
    if complete:
        evidence.append("modules.order present for: " + abbreviate(complete))
    observe(
        state,
        "kernel.installed",
        "kernel-installation",
        Confidence.HIGH if complete else (Confidence.MEDIUM if entries else Confidence.LOW),
        Status.INSTALLED if entries else Status.ABSENT,
        evidence,
    )
    return entries


def _detect_mkinitcpio(state: ObservedState, root: str, execute: Execute) -> bool:
    """Detect initramfs configuration and the mkinitcpio CLI."""
    evidence: list[str] = []
    configured = False
    if path_exists(root, "/etc/mkinitcpio.conf"):
        evidence.append("/etc/mkinitcpio.conf exists")
        configured = True
    presets = find_files(root, "/etc/mkinitcpio.d", suffixes=(".preset",), max_files=20)
    if presets:
        evidence.append("presets: " + abbreviate(presets))
        configured = True
    rc, stdout, _ = run(execute, "mkinitcpio --version")
    tool = command_ok(rc)
    if tool:
        evidence.append("mkinitcpio CLI: " + (first_line(stdout) or "responds"))

    confidence = Confidence.HIGH if configured and tool else (Confidence.MEDIUM if configured or tool else Confidence.LOW)
    status = Status.CONFIGURED if configured else (Status.INSTALLED if tool else Status.ABSENT)
    observe(state, "boot.mkinitcpio", "initramfs-generation", confidence, status, evidence)
    return configured or tool


def _detect_efi(state: ObservedState, root: str, execute: Execute) -> tuple[bool, str]:
    """Detect EFI firmware mode; return ``(detected, findmnt_output)``."""
    firmware_dir = is_dir(root, "/sys/firmware/efi")
    rc, stdout, _ = run(execute, "findmnt -rn -o TARGET,SOURCE,FSTYPE")
    mount_output = stdout if command_ok(rc) else ""
    efivars = any(line.split()[0] == "/sys/firmware/efi/efivars" for line in lines(mount_output) if line.split())
    evidence: list[str] = []
    if firmware_dir:
        evidence.append("/sys/firmware/efi exists")
    if efivars:
        evidence.append("findmnt: efivarfs mounted at /sys/firmware/efi/efivars")
    detected = firmware_dir or efivars
    confidence = Confidence.HIGH if firmware_dir and efivars else (Confidence.MEDIUM if detected else Confidence.LOW)
    status = Status.RUNNING if detected else Status.ABSENT
    observe(state, "boot.efi", "efi-firmware", confidence, status, evidence or ["no EFI firmware evidence"])
    return detected, mount_output


def _detect_esp(state: ObservedState, root: str, findmnt_output: str) -> bool:
    """Corroborate the EFI System Partition via findmnt and fstab."""
    targets = {"/boot", "/efi", "/boot/efi"}
    mount_evidence: list[str] = []
    for line in lines(findmnt_output):
        fields = line.split()
        if len(fields) >= 3 and fields[0] in targets and fields[2].lower() in ("vfat", "fat", "fat16", "fat32"):
            mount_evidence.append("findmnt: " + " ".join(fields[:3]))

    fstab_evidence: list[str] = []
    for record in parse_fstab(read_file(root, "/etc/fstab")):
        if record["target"] in targets and record["fstype"].lower() in ("vfat", "fat", "fat16", "fat32"):
            fstab_evidence.append(
                "fstab: {target} {source} {fstype}{options}".format(
                    target=record["target"],
                    source=record["source"],
                    fstype=record["fstype"],
                    options=(" " + record["options"]) if record["options"] else "",
                )
            )

    detected = bool(mount_evidence or fstab_evidence)
    evidence = mount_evidence + fstab_evidence
    if not evidence:
        evidence.append("no vfat mount at /boot, /efi or /boot/efi found")
    confidence = Confidence.HIGH if mount_evidence and fstab_evidence else (Confidence.MEDIUM if detected else Confidence.LOW)
    observe(
        state,
        "boot.esp",
        "efi-system-partition",
        confidence,
        Status.CONFIGURED if detected else Status.ABSENT,
        evidence,
    )
    return detected


def _detect_efibootmgr(state: ObservedState, execute: Execute) -> tuple[bool, str]:
    """Check firmware boot-entry management and return its raw output."""
    rc, stdout, stderr = run(execute, "efibootmgr -v")
    ok = command_ok(rc)
    evidence = [f"efibootmgr -v -> rc={rc}"]
    if ok:
        evidence.append("entries: " + abbreviate(lines(stdout), limit=6))
    elif stderr.strip():
        evidence.append("stderr: " + stderr.strip()[:200])
    observe(
        state,
        "boot.efibootmgr",
        "boot-entry-management-tool",
        Confidence.HIGH if ok else Confidence.LOW,
        Status.RUNNING if ok else Status.ABSENT,
        evidence,
    )
    return ok, stdout if ok else ""


def _detect_bootloaders(state: ObservedState, root: str, installed: list[str], efi_output: str, efi: bool, esp: bool) -> None:
    """Determine the active bootloader with explicit confidence ceilings."""
    entry_lines = lines(efi_output)
    winners: list[tuple[int, bool, bool, bool, dict[str, object], list[str]]] = []

    for candidate in _BOOTLOADERS:
        name = str(candidate["name"])
        token = str(candidate["token"])
        packages = tuple(str(p) for p in candidate["packages"])  # type: ignore[arg-type]
        entry_tokens = tuple(str(p) for p in candidate["entry_tokens"])  # type: ignore[arg-type]
        configs = tuple(str(p) for p in candidate["configs"])  # type: ignore[arg-type]

        evidence: list[str] = []
        present_packages = [pkg for pkg in packages if pkg in installed]
        if present_packages:
            evidence.append("installed package: " + ", ".join(present_packages))

        present_configs = [cfg for cfg in configs if path_exists(root, cfg)]
        if name == "systemd-boot":
            for loader_dir in ("/boot/loader/entries", "/efi/loader/entries"):
                entries = find_files(root, loader_dir, suffixes=(".conf",), max_files=20)
                if entries:
                    present_configs.append(loader_dir + " (" + abbreviate(entries) + ")")
        if present_configs:
            evidence.append("config: " + abbreviate(present_configs))

        matching_entries = [
            line for line in entry_lines if any(word in line.lower() for word in entry_tokens)
        ]
        if matching_entries:
            evidence.append("EFI boot entry: " + abbreviate(matching_entries, limit=3))

        has_package = bool(present_packages)
        has_config = bool(present_configs)
        has_entry = bool(matching_entries)

        if has_entry and has_config:
            confidence, status = Confidence.HIGH, Status.RUNNING
        elif has_entry:
            confidence, status = Confidence.MEDIUM, Status.RUNNING
        elif has_config:
            confidence, status = Confidence.MEDIUM, Status.CONFIGURED
        elif has_package:
            confidence, status = Confidence.MEDIUM, Status.INSTALLED
            evidence.append("package alone caps confidence at MEDIUM (active bootloader not proven)")
        else:
            continue

        if not has_entry:
            evidence.append("no firmware boot entry corroboration")

        observe(state, f"bootloader.{name}", token, confidence, status, evidence)
        winners.append((confidence_rank(confidence), has_entry, has_config, has_package, candidate, evidence))

    if not winners:
        observe(
            state,
            "bootloader",
            "unknown-bootloader",
            Confidence.LOW,
            Status.ABSENT,
            [
                "no bootloader package, config or EFI boot entry identified",
                f"EFI firmware detected: {efi}; ESP detected: {esp}",
            ],
        )
        return

    winners.sort(key=lambda item: item[:4], reverse=True)
    best = winners[0]
    candidate = best[4]
    token = str(candidate["token"])
    rank, has_entry, has_config, _has_package = best[:4]
    confidence = Confidence.HIGH if rank >= confidence_rank(Confidence.HIGH) else Confidence.MEDIUM
    status = Status.RUNNING if has_entry else (Status.CONFIGURED if has_config else Status.INSTALLED)
    evidence = list(best[5])
    evidence.append(f"EFI detected: {efi}; ESP detected: {esp}")
    observe(state, "bootloader", token, confidence, status, evidence)


def discover_kernel_boot(state: ObservedState, root: str = "/", execute: Execute | None = None) -> ObservedState:
    """Populate *state* with kernel and boot-chain observations.

    Args:
        state: An :class:`~core.ObservedState` to enrich.  ``state.packages``
            is consulted for package-level bootloader evidence; if it is empty
            (for example when this function is called standalone) only files,
            commands and EFI entries contribute.
        root: Filesystem prefix for ``/usr/lib/modules``, ``/boot``, ``/efi``,
            ``/sys/firmware/efi`` and ``/etc/fstab``.
        execute: Injected command executor returning ``(rc, stdout, stderr)``.

    Returns:
        The same *state*.  Bootloader confidence never exceeds MEDIUM without
        an observed EFI boot entry plus a config file.
    """
    ex = as_execute(execute)
    _detect_running_kernel(state, ex)
    installed_kernels = _detect_installed_kernels(state, root)
    _detect_mkinitcpio(state, root, ex)
    efi, findmnt_output = _detect_efi(state, root, ex)
    esp = _detect_esp(state, root, findmnt_output)
    _efibootmgr_ok, efi_output = _detect_efibootmgr(state, ex)

    # Installed kernel packages corroborate module directories; keep both.
    installed_names = set(state.packages) | set(installed_kernels)
    _detect_bootloaders(state, root, sorted(installed_names), efi_output, efi, esp)
    return state
