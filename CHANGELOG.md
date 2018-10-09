**0.4**

- SeaSalt_Keychain
  * Added config keys for read-only mode, lock mode, lock ttl, and storage checksums
  * Restructured keychain to storing keyconfs in their own storage keys
  * Lock mode enabled by default (opening a key conf will obtain a write lock for the session)

**0.3**

- SeaSalt_Keychain
  * Added methods: backup, check, clean, read_meta, scan
  * Write now store file metadata
  * Implemented password strength enforcement
- Docs updated and cleaned up more

**0.2**

- Added SeaSalt_Keychain
- Added SeaSalt_Tools.randomString
- SeaSalt class renamed to SeaSalt_Common (with alias on SeaSalt)
- Full documentation

**0.1**

- Base project code done with classes for password hashing, aead encryption, secret box, and a few tools.
