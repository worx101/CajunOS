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
8. base userland, kernel, init, bootloader, image, and clean-room boot tests.

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
