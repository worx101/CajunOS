# Native developer seed signing keys

Stage 9B does not trust a network keyserver or a mutable system keyring. The
project/maintainer key objects are fetched only from the exact HTTPS URLs in
`manifests/native-developer-archives.json`, byte-hash checked against
`locks/native-developer-archives.lock.json`, and supplied to an isolated
`gpgv` invocation as a component-specific keyring.

ASCII-armored key objects are decoded with strict CRC-24 checking. Both their
downloaded bytes and derived binary keyring bytes are locked. The GMP key is
already a binary OpenPGP keyring. No private key belongs in this directory or
in a CajunOS image.
