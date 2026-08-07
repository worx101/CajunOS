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

See [`docs/bootstrap.md`](docs/bootstrap.md) for the staged bootstrap design,
workspace contract, and verification rules.

> Status: bootstrap in progress. CajunOS is an experiment and is not ready for production use.
