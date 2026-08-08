# CajunOS bootstrap

CajunOS starts with current development branch tips from each component's
canonical repository. A moving upstream branch chooses inputs; the generated
lockfile turns one integration attempt into an exact, reviewable source set.

This is not an LFS package list or source bundle. Debian is only the forge host.
Its compiler and development packages are bootstrap tools and are not copied
into the CajunOS target filesystem.

## Workspace contract

The orchestration expects the following paths beneath `CAJUNOS_ROOT`, which
defaults to `/srv/cajunos`:

```text
project/    CajunOS orchestration checkout
upstream/   canonical upstream checkouts
work/       disposable out-of-tree build directories
sysroot/    staged CajunOS root filesystem
tools/      immutable toolchain prefixes plus the current symlink
cache/      compiler and download caches
artifacts/  build products and machine-readable receipts
logs/       fetch and build logs
```

Source trees and build directories stay separate. A build step refuses a
source tree whose commit, tree, origin, or declared licenses differ from the
committed lockfile. Sysroots are cohort-versioned and tool prefixes are
input-versioned; successful validation atomically advances `tools/current`.
Builds hold the same source-operation lock used by synchronization for their
entire validation, compilation, receipt, and publication lifetime.

Sysroot changes are immutable snapshots beneath
`sysroot/<cohort>/snapshots/<build-id>`. The relative `current` link selects
the active snapshot, while `sysroot/<cohort>/usr` resolves through
`current/usr`. A stage publishes and validates its snapshot before atomically
advancing `current`; an idempotent rerun never rewinds a later snapshot.

## Source acquisition

`scripts/fetch.py update-lock` is the only operation that advances moving
upstream branches. `scripts/fetch.py sync` instead consumes the committed lock
and never selects a newer revision. Both perform one component at a time and:

1. accepts only repository URLs declared in the manifest;
2. refuses dirty or structurally unexpected existing checkouts;
3. fetches either an explicit upstream branch ref for a lock update or the
   exact committed object ID for a locked synchronization;
4. uses a temporary sibling directory for a new clone and renames it only after
   Git connectivity verification succeeds; and
5. atomically writes commit, tree, timestamp, subject, branch, and actual remote
   into `locks/bootstrap.lock.json`.

Lock updates use HTTPS by default. The official anonymous Git transports
documented by GNU projects require the explicit `--allow-unauthenticated`
option because Sourceware can rate-limit HTTPS. The lock records whether each
selection used an authenticated transport; Git object consistency alone is not
presented as source authenticity. Building a cohort with such a lock also
requires `CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1`; this is an explicit risk
acknowledgement and does not disable any content or provenance validation. A
locked synchronization may use another declared repository only when its
transport is at least as authenticated as the repository recorded in the lock.

## Toolchain stages

The initial target tuple is `x86_64-cajunos-linux-gnu`. Target binaries use the
`x86-64-v2` baseline; the forge may use its host CPU to build them but target
code must not use `-march=native`.

The planned bootstrap sequence is:

1. Binutils cross assembler/linker into `tools/`.
2. Minimal GCC C cross compiler without a target libc.
3. Linux userspace headers into `sysroot/<cohort>/usr/include` through the
   active immutable snapshot.
4. glibc headers and startup objects.
5. Static bootstrap GCC target runtime (`libgcc`) in a derived immutable tools
   prefix.
6. complete glibc.
7. complete C/C++ cross compiler and runtime.
8. locked kernel plus deterministic minimal initramfs, proven by diskless
   serial-console boots.
9. base userland, init, bootloader, image, and clean-room boot tests.

Each stage gets a unique log, immutable build ID, preserved license bundle,
a recursive inventory of installed files, symlinks, directories, modes, and
hashes, plus a machine-readable receipt. Reaching a chroot is
not a release criterion: the output must boot independently in a separate QEMU
VM with no Debian builder disk attached.

## Current milestone

`scripts/build-binutils-stage1.sh` builds only the first cross-tools and verifies
them by assembling, linking, and executing a freestanding x86-64 ELF probe. It
builds from a clean committed orchestration checkout, stages installation under
the workspace, and publishes only after all checks pass. It neither installs
target libraries nor writes into the Debian root filesystem.

`scripts/build-gcc-stage1.sh` consumes an exact, fully revalidated immutable
Binutils receipt and builds only GCC's `all-gcc`/`install-gcc` targets. It binds
the compiler to that assembler/linker, an empty cohort sysroot, the
`x86-64-v2`/generic target baseline, and a C-only single-threaded bootstrap
contract. Publication requires target/sysroot/default-option checks, proof that
host include paths did not leak, a freestanding compile/link/run probe, and
confirmation that no target runtime or startup objects were installed.
Current GCC trunk tries to run `fixincludes` even for a `--without-headers`
compiler and then requires a system-header directory to exist. This headerless
stage disables `fixincludes` explicitly; it has no target headers to repair,
and the real CajunOS cohort sysroot remains empty until the Linux UAPI headers
stage.

`scripts/install-linux-headers.sh` runs the locked kernel's `headers_install`
target twice in independent out-of-tree builds and requires identical paths,
types, modes, content hashes, and symlink targets. It then checks the exported
x86-64 UAPI with the sealed stage-one cross compiler, publishes an immutable
cohort snapshot, and records the Linux, GCC, and nested Binutils provenance in
its receipt.

`scripts/install-glibc-headers-startfiles.sh` copies that sealed Linux snapshot
twice, independently configures the locked glibc source for the CajunOS target,
and uses the current upstream `install-headers` and `csu/subdir_lib` targets.
It publishes public glibc headers with only `crt1.o`, `crti.o`, and `crtn.o`.
The stage explicitly prevents host C++ header discovery and requires identical
complete snapshot inventories, header-search and ELF probes, unchanged base
content, and an exact receipt chain back through Linux, GCC, and Binutils. It
does not publish a real or placeholder libc, GCC runtime, or dynamic loader.

`scripts/build-libgcc-bootstrap.sh` consumes the sealed GCC compiler and the
active glibc headers/startfiles snapshot without changing either one. It builds
current GCC's target runtime twice in independent out-of-tree builds with
shared libraries, threads, multilib, and gcov disabled. Publication makes an
ordinary copy of the stage-one compiler prefix and overlays only upstream's
static `libgcc`, unwind/gcov headers, and x86-64 target CRT helpers. The driver
must relocate to the new prefix and resolve every runtime file there; the
cohort sysroot must remain byte-for-byte unchanged. No `libgcc_s`, functional
libc, dynamic loader, or profiling library is claimed at this milestone. The
unselected final-prefix directory is established before persistent probes run,
so runtime lookups, symbol output, and the retained linker map never depend on
disposable build paths. Completed and idempotent validation replays those
semantic lookup, archive, symbol, and linker-map contracts in addition to
checking their receipt-bound hashes.

`scripts/build-glibc-complete.sh` consumes the sealed headers/startfiles
snapshot and the selected corrected bootstrap-libgcc prefix. It performs two
independent full builds and installs, permits exactly the upstream-generated
replacement of `gnu/stubs-64.h`, normalizes glibc's four hard-linked `getconf`
entry points into independent files, and publishes an immutable functional
libc snapshot. Current GCC trunk automatically links `-latomic_asneeded`; the
stage uses GCC's explicit `-fno-link-libatomic` bootstrap cycle breaker and
rejects any installed ELF that still needs libatomic, shared libgcc, an
escaping runtime path, or an executable stack. Exactly fourteen upstream gconv
modules may retain `RUNPATH=$ORIGIN`, which resolves to their own sealed module
directory. The snapshot uses
`lib64 -> usr/lib`, while the cohort uses `lib64 -> current/usr/lib`, so GCC's
default `/lib64/ld-linux-x86-64.so.2` interpreter follows the same atomic
snapshot selector as `/usr`. Dynamic, pthread, static, loader-resolution, and
`getconf` probes are replayed during completed validation. Shared GCC runtime,
libatomic, and C++ remain deferred to the following compiler/runtime stage.

`scripts/build-gcc-complete.sh` consumes that sealed functional-glibc snapshot
and the selected corrected bootstrap-libgcc prefix without changing either
one. It configures exactly GCC compiler proper plus target `libgcc`, libatomic,
and libstdc++, then builds and installs those four targets twice in independent
out-of-tree builds. The target runtime is compiled for the
`x86-64-v2`/generic baseline with GCC's automatic libatomic link temporarily
disabled to break the runtime build cycle; the installed driver retains its
normal as-needed libatomic behavior. Debug information is disabled explicitly
for libgcc through `LIBGCC2_DEBUG_CFLAGS=-g0`, and libstdc++ precompiled headers
are disabled so the two sealed installs have a reproducible complete inventory.

Publication derives a new immutable tools prefix from the bootstrap-libgcc
base and requires identical independent inventories, unchanged base and
sysroot dependency inventories, and a receipt-bound provenance chain. Compiler
driver, C++23 exceptions/threads, dynamic and static execution, shared-libgcc,
and 16-byte atomic probes must all resolve only inside the final prefix and the
sealed glibc snapshot. A program that does not use out-of-line atomics must not
gain a libatomic dependency, while the explicit atomic probe must resolve
`libatomic.so.1`. Completed validation replays those probes and inventory
contracts; failed unselected candidates are quarantined, and the tools selector
advances only after the permanent prefix, artifacts, and receipt have all been
validated.

`scripts/build-kernel-first-boot.sh` consumes the locked Linux source, the
selected complete GCC prefix, and the active complete-glibc snapshot without
changing any of them or advancing either selector. The committed
`configs/x86_64-first-boot.config` is a fully resolved, compiler-bound x86-64
configuration for a small built-in serial-console kernel: modules, SMP,
networking, block storage, PCI, graphics, USB, sound, EFI, and ACPI are absent.
The kernel retains ELF execution, an external raw initramfs, devtmpfs, procfs,
sysfs, tmpfs, and one 8250 console. `CONFIG_WERROR` is disabled and the build
applies the narrow `-Wno-constant-logical-operand` compatibility exception
required by the locked GCC 17 snapshot; the kernel itself is not forced through
userspace `-march` flags.

This is a diagnostic first-boot kernel, not a deployable security baseline. Its
minimal proof configuration intentionally omits CPU mitigations, KASLR and a
relocatable image, stack protection, fortification, the security framework,
networking, and storage. Those facilities return in later system-image stages
under their own explicit contracts. `CONFIG_DEVTMPFS_MOUNT=y` does not mount
devtmpfs when the root is initramfs, so the archive always carries the attested
`/dev/console` node needed before PID 1 can mount anything.

Two independent out-of-tree builds must produce byte-identical `bzImage`
files, static `/init` executables, and raw `newc` archives. Each archive is
generated with that build's own `usr/gen_init_cpio`, the locked source epoch,
and an exact minimal topology containing `/init`, `/dev/console`, `/dev/null`,
`/proc`, `/sys`, and `/run`. The static init is linked explicitly against the
sealed glibc snapshot for `x86-64-v2`, carries no interpreter or dynamic
dependency, requires PID 1, verifies its exact kernel release and immutable
build ID, mounts procfs, and accepts exactly one
`cajunos.first_boot=1` command-line token.

Publication requires both a positive boot and a negative fail-closed boot under
QEMU TCG using an explicit `pc-q35-10.0` machine, one `Nehalem-v1` CPU, one
8250 serial device, no NIC, no default devices, and no builder disk. The serial
evidence must reach `CAJUNOS_KERNEL_FIRST_BOOT_OK` only for the positive boot;
the negative boot must emit an exact `CAJUNOS_KERNEL_FIRST_BOOT_FAIL` reason and
must never emit the success marker. Receipts bind the source and orchestration
commits, complete dependency chain, resolved config, build environment,
inventories, hashes, QEMU topology, and both serial transcripts. Failed
candidates are quarantined, and completed replay reruns all receipt, artifact,
and boot contracts without mutating the sealed toolchain or sysroot.

### Base system image

`scripts/build-base-system-image.sh` begins milestone 9 without changing the
sealed four-component bootstrap lock. BusyBox, GRUB, and the Gnulib revision
named by GRUB's `bootstrap.conf` live in `manifests/base-system.json` and its
reviewed exact-commit lock. The stage starts BusyBox from `allnoconfig`, applies
the committed fragment, and resolves it with the locked revision's `oldconfig`
using explicit stdin EOF because that revision has no `olddefconfig`. It disables
the `tc` applet that is incompatible with the locked Linux 7.2 UAPI, rejects any
nonexistent-symbol assignment warning, and carries both `ARCH` and `CROSS_COMPILE`
through the install target so installation cannot rebuild with the Debian host
compiler. Login uses BusyBox's internal crypt implementation with SHA-256/512
support because the sealed static sysroot deliberately has no external libcrypt.

The deployable kernel restores Q35/Proxmox essentials as built-ins: SMP, ACPI,
PCI, GPT parsing, VirtIO block/SCSI/network, IPv4, ext4, devtmpfs, and serial.
It also restores KASLR, CPU mitigations, strong stack protection, fortification,
hardened usercopy, and the Linux security framework. Modules remain disabled
so the kernel and image cannot drift independently.

Two independent root trees are normalized to the Linux commit epoch and
populated into fixed-UUID ext4 images under one fakeroot session that explicitly
maps every inode to uid/gid 0. The filesystem hash seed and feature set are
fixed, and the completed images must be byte-identical. Filesystem creation
ignores `/etc/mke2fs.conf`; block, inode, and flex-group geometry plus the exact
feature set are supplied explicitly and replayed from the superblock. A fixed-GUID
GPT gives GRUB an EF02 BIOS Boot partition and CajunOS its root partition. GRUB is
bootstrapped and built from the locked upstream sources; no host
`grub-install` is used. Its independent source and build paths are mapped to
stable logical paths, and both builds use `/usr` as their logical prefix with
separate `DESTDIR` roots so GRUB's compiled `__FILE__` strings and generated
tools cannot encode the A/B workspace names. A small attested installer
implements the fixed-layout i386-pc subset of upstream `setup.c`, embedding the independently built
`core.img` without loop devices, mounts, or root privileges. Linux selects the
root with its GPT `PARTUUID`; filesystem UUID is used only by GRUB to locate
`grub.cfg`.

The positive clean-room probe attaches only the raw disk and a user-mode
VirtIO NIC to a pinned Q35/SeaBIOS TCG machine. Init mounts the virtual filesystems,
proves that the mounted root's major/minor resolves to the expected PARTUUID,
configures `eth0` using a renewing DHCP daemon, and emits exact serial markers.
It accepts the kernel's automatic devtmpfs mount only after `/proc/self/mountinfo`
proves one `/dev` devtmpfs instance with the required root mode and console;
otherwise it creates that mount itself or fails closed.
The static BusyBox contract includes formatted `stat` output, shell arithmetic,
the `test`/`[` pair, and distinct `halt`, `poweroff`, and `reboot` applets so
those checks and every shutdown path are available in the sealed root.
The immutable raw transcript retains GRUB's deterministic serial-terminal
clear-screen prologue. Validation removes only that exact byte-zero sequence
when creating the separate normalized transcript and rejects every other NUL,
escape, or repeated prologue.
The negative probe direct-loads the same kernel against the same GPT root image
with the wrong locked token; it does not exercise GRUB a second time. It must
power off after the exact `cmdline-token` failure without emitting build, root,
network, or success markers. Two complete trees, ext4 images, raw disks, serial transcripts,
licenses, dependency receipts, host inputs, and selector immutability are bound
into the receipt and replayed before an existing result is accepted. SSH and
the native package toolchain remain explicitly deferred to the developer-seed
stage.

The QEMU proof does not by itself claim the final tower1 storage contract.
Before a VM or template is accepted on tower1, deployment must boot the image
through its actual VirtIO-SCSI controller, enable the ext4 journal on the grown
root filesystem, run a clean forced `fsck`, and retain evidence for both the
controller-backed boot and filesystem transition. Those are mandatory
deployment gates rather than properties of this deterministic 9A seed image.

### Native developer seed

`scripts/build-native-developer-seed.sh` implements Stage 9B. It consumes one
explicit Stage 9A build ID and revalidates that receipt, raw disk, root
inventory, kernel configuration, dependency receipts, and unchanged tool and
sysroot selectors before any build tool runs. There is no `latest` lookup and
the stage never advances a selector. Its separate locked inputs are Dropbear's
exact Git commit and authenticated release archives for GNU Make, GMP, MPFR,
and MPC. Detached signatures are verified before the global source lock is
taken, then the same cached bytes are recaptured and extracted under that lock.

Two Canadian-cross builds use `x86_64-pc-linux-gnu` as build and
`x86_64-cajunos-linux-gnu` as both host and target. Each independently installs
native Binutils, GCC and G++, libgcc, libatomic, libstdc++, GNU Make, static
BusyBox, and static key-only Dropbear. Regular-file hardlinks are converted to
independent files before canonical inventory and filesystem population so the
retained tree and an inode-by-inode ext4 replay have identical topology. The
locked sources remain under `/usr/src/cajunos` for package work. Exact upstream
public algorithm test vectors embedded in C remain source-hash-bound, while
three standalone PEM private-key fixtures and Dropbear's embedded fuzz host-key
fixture are hash-bound, recorded, and omitted. This is a
package-build-capable seed, not proof of a full native self-host or a final
package-management policy.

The Stage 9A GPT identity, protective MBR, GRUB boot code, BIOS Boot partition,
root PARTUUID, and filesystem UUID are retained while the sparse raw disk grows
to 16 GiB. Partition 2 grows to the new GPT boundary and contains an exact
12 GiB ext4 filesystem, leaving additional in-partition growth reserve. The
filesystem is first created without a journal using `MKE2FS_CONFIG=/dev/null`,
fixed geometry, feature set, hash seed, ownership, and source epoch. A fixed
64 MiB internal journal is then added with fake-time-bound `tune2fs`. Exact
superblock fields and features, A/B byte identity, clean state, and forced
read-only `fsck` are publication gates.

The build accepts exactly one approved Ed25519 public-key file and creates
`/root/.ssh/authorized_keys` at mode 0600 during root assembly; no placeholder
key file is tracked. The forge rejects private-key inputs and SSH agent sockets.
Dropbear compiles password, PAM, forwarding, SFTP, inetd, and public-key option
code out, generates a unique Ed25519 host key atomically on first boot, and
sends authentication logs to the serial console. Owner-key possession is
proved separately from a trusted host through a loopback tunnel with strict
host-key pinning, no agent forwarding, an interactive PTY, and a namespaced
SSHSIG response. The request binds the build, challenge, port, canonical host
key, host-key hash, and owner public-key hash; candidate and completed replay
verify those semantics against the owner boot's serial evidence before
accepting the signature. The trusted side closes the response and signature,
then creates a hash-binding ready sentinel. Handoff uploads all three under
temporary names and atomically renames the response and signature before
renaming the sentinel last; the forge ignores incomplete or hash-mismatched
ingress until the bounded proof timeout.

Publication boots only qcow2 overlays backed by the pristine raw candidate.
No guest receives host filesystem sharing or network egress. Positive gates
cover disk-only BIOS/GRUB boot, DHCP, one canonical
`CAJUNOS_NATIVE_DEVELOPER_IPV4` serial marker, negative/no-key/wrong-key/password
SSH attempts, public-key and PTY success, C/C++/assembly/static/libatomic/Make
probes, a native Dropbearkey rebuild, persistent nonce and host key after clean
reboot, distinct first-boot host keys on independent clones, and forced fsck of
every booted overlay. A separate wrong-token boot must fail closed.

Completed replay rechecks both retained root trees, both ext4 images, both raw
disks, source and host inputs, receipt inventories, private-material scans,
owner request/serial/response/signature binding, a fresh disk-only overlay boot,
and a fresh wrong-token boot. Failure quarantines unpublished work. The only
future template source is the pristine, never-booted Stage 9B raw artifact;
booted overlays are permanently ineligible because deleted/generated private
key blocks can remain recoverable.

Stage 9B does not deploy a VM on tower1, create a Proxmox template, prove the
VirtIO-SCSI production controller path, or establish final VM sizing. Those are
the following deployment milestone, which must start from the pristine artifact
and retain its own boot, direct-SSH, storage-growth, and template evidence.
