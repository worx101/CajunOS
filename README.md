# CajunOS

CajunOS is a just-for-fun, experimental Linux system assembled directly from upstream project repositories.

## Ground rules

- Pull source from each project's canonical upstream repository.
- Track current upstream code while recording the exact integrated commit for reproducibility.
- Do not use Linux From Scratch source bundles or its pinned package set.
- Patch and adapt upstream code when integration requires it.
- Preserve source provenance, upstream licenses, local patches, and build logs.

## Bootstrap

The first milestone builds an `x86_64-cajunos-linux-gnu` cross-toolchain on the
dedicated CajunOS forge. Component selection lives in
[`manifests/bootstrap.json`](manifests/bootstrap.json), while
[`locks/bootstrap.lock.json`](locks/bootstrap.lock.json) records the exact
upstream commits used by a build.

The committed bootstrap cohort records that GNU repository HTTPS returned
HTTP 429 during selection, so Binutils, GCC, and glibc used their projects'
declared anonymous Git transports. That exception is explicit in the lock;
future lock updates prefer authenticated HTTPS and require an opt-in before
falling back.

```sh
make fetch
make validate
CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 make binutils-stage1
CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 make gcc-stage1
CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 make linux-headers
CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 make glibc-headers-startfiles
CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 make libgcc-bootstrap
CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 make glibc-complete
CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 make gcc-complete
CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 make kernel-first-boot
make fetch-base-system
CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 make base-system-image
make fetch-native-developer
export CAJUNOS_GPGV=/sealed/path/gpgv
export CAJUNOS_GPGV_LIBRARY_ROOT=/sealed/path/gpgv-library-root
make validate-native-developer
CAJUNOS_BASE_SYSTEM_BUILD_ID=base-system-... \
CAJUNOS_OWNER_SSH_PUBLIC_KEY=/trusted/path/cajunos-owner.pub \
CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 make native-developer-seed
```

That environment variable is required only because this committed cohort
records anonymous Git transports after the GNU HTTPS endpoints returned HTTP
429. It acknowledges the recorded transport risk; commit, tree, origin, and
license validation remain mandatory.

The first GCC stage builds compiler proper only. The Linux stage installs the
locked userspace API headers, and the glibc bootstrap stage adds public libc
headers plus `crt1.o`, `crti.o`, and `crtn.o` in a new immutable snapshot. The
next stage derives an immutable compiler prefix containing static bootstrap
`libgcc` and GCC's target CRT helpers. The complete-glibc stage then publishes
functional libc, pthread support, the dynamic loader, static libc, NSS/gconv
modules, and libc utilities in a reproducible derived snapshot. The complete
GCC stage derives the final bootstrap tools prefix and adds the C++ compiler,
shared `libgcc_s`, libatomic, and libstdc++ against that sealed glibc snapshot.
The kernel-first-boot stage then builds the locked x86-64 kernel twice, creates
two deterministic raw initramfs archives containing a sealed static PID 1, and
requires matching positive and fail-closed serial-console boots in a diskless
QEMU machine. It publishes boot artifacts and evidence without advancing the
tool or sysroot selectors.

The base-system-image stage then consumes a separate reviewed lock for BusyBox,
GRUB, and GRUB's exact Gnulib bootstrap input. It builds a deployable kernel,
static base userland, deterministic ext4 filesystem, and deterministic GPT/BIOS
raw disk twice. Publication requires a disk-only GRUB boot with renewing DHCP over
VirtIO and a separate fail-closed command-line probe. SSH and the native package
toolchain intentionally remain in the following developer-seed milestone.

The native-developer-seed stage consumes one explicit sealed base-system
receipt and grows its raw GPT disk to 16 GiB with a reproducible 12 GiB
journaled ext4 root. It installs native Binutils, GCC/G++, libgcc, libatomic,
libstdc++, GNU Make, static BusyBox, and static key-only Dropbear together with
the locked source trees. Two independent builds must match byte-for-byte, then
QEMU proves disk-only GRUB boot, canonical IPv4 serial discovery, public-key
SSH with a PTY, clean persistence across reboot, and native package rebuilds.
The approved owner key is installed from a public-key file during assembly;
no private key or agent reaches the forge. Only the pristine, never-booted raw
artifact is eligible for the later tower1 VM/template milestone.

Before first boot on tower1, the privileged
`prepare-native-developer-deployment` target derives—not replaces—the sealed
16 GiB artifact. It creates a 64 GiB GPT/root-ext4 OS disk and a separate
256 GiB GPT/ext4 package-build disk. The derivative root receives the exact
build PARTUUID, filesystem UUID, sentinel hash, and persistent `/etc/fstab`
intent; the build disk receives the matching sentinel. Boot discovers the
partition by identity rather than `/dev/sdX`, verifies its geometry and ext4
identity, mounts it at `/build` with executable package-workspace semantics,
and emits `CAJUNOS_NATIVE_DEVELOPER_BUILD_VOLUME_OK` before SSH.
The caller must supply the independently recorded Stage 9B receipt SHA-256;
deriving that trust anchor from the receipt at deployment time is forbidden.
Outputs are staged in private directories under root-owned, non-group/other-
writable ancestor chains, replayed with forced read-only fsck and exact file
checks, and only then completed by publishing the evidence JSON. Two separate
preparations with the same identity tuple must produce byte-identical OS and
build disks before either is eligible for import. The guest validates the build
PARTUUID, ext4 UUID/type/label, exact capacity, and sentinel at runtime; the GPT
build-disk GUID is validated offline and is explicitly not a runtime claim.

The eventual template source is a stopped, never-booted imported derivative.
Boot and SSH acceptance run only against disposable full clones; after those
clones pass and are destroyed, the untouched source may become the template.
Networking is DHCP by default and the pristine/template root omits
`/etc/cajunos-static-network`. A particular VM may receive that strict
three-line static-network contract only after its first DHCP/direct-SSH proof;
the generic template never receives an instance address.

See [`docs/bootstrap.md`](docs/bootstrap.md) for the staged bootstrap design,
workspace contract, and verification rules.

> Status: bootstrap in progress. CajunOS is an experiment and is not ready for production use.
