# sunshineos-repo

The pacman repository and the "convert any Arch system" plan for [Sunshine OS](https://github.com/tak0dan/SunshineOS).

Packages are published as assets of a GitHub Release (`repo`), so a plain Arch machine can use them with only pacman:

```ini
# /etc/pacman.conf
[sunshine]
SigLevel = Optional TrustAll      # until packages are signed, see TODO.md
Server = https://github.com/tak0dan/sunshineos-repo/releases/download/repo
```

pacman follows the release redirects, so `pacman -Sy sunshine-base` works like with any other repository.

## How an Arch system becomes Sunshine OS

`sunshine-doctor --fix` compares the machine with a desired state and repairs one thing at a time. Every step is
idempotent, so running it in a loop until it exits 0 converges any Arch system, even a broken one that has only
pacman (the same idea as `garuda-health --fix`).

| Pass | What it makes true | Needs |
|------|--------------------|-------|
| 1 | pacman works: no stale lock, keyring initialised, mirrors answer, no half-finished upgrade | pacman |
| 2 | the `[sunshine]` repository and its key are in `pacman.conf` | pacman |
| 3 | `sunshine-base` is installed (a meta-package that pulls the whole package set) | the repo from pass 2 |
| 4 | configs, hooks, scripts and the store are in place; services enabled | `sunshine-base` |
| 5 | identity (`os-release`, `issue`, branding) restored; initramfs and GRUB menu rebuilt (including the NixOS entry) | all above |

Rules: it never removes your packages or your files; it does not touch the bootloader or partitions unless
`--convert` is given; each pass prints what it changed, and a pass that changes nothing means "done".

## Layout (planned)

```
packages/      PKGBUILDs of everything that is not in the official repos (sunshine-base, sunshine-update, sunshine-store, ...)
package-list/  the single list of packages; the ISO build and sunshine-base both read it
scripts/       build-repo.sh (build, sign, repo-add), publish.sh (upload to the `repo` release)
TODO.md        steps and open decisions
```

`sunshine-update` is the dedicated package that owns `/usr/bin/sunshine-update` and ships the
Evolution Engine; `sunshine-base` keeps the update helpers/notifier but no longer installs that
entry point.

See [TODO.md](TODO.md).
