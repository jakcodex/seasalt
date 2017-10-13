# SeaSalt

A simple Javascript class making Libsodium easier to use.

See it in action here: <a href="https://jakcodex.github.io/seasalt/seasalt.html">https://jakcodex.github.io/seasalt/seasalt.html</a>

## Example

#### AEAD Encryption

Utilizes the XCHACHA20-POLY1305-IETF 2-way Cipher

```js
let seasalt = new SeaSalt({
	passphrase: 'a3a44974a290878ad341befe2b96dc561d7692e02ab39c7bef26c67f37a5f46e'
});
let ciphertext = seasalt.encrypt('test');
let decrypted = seasalt.decrypt(ciphertext);

// or

let seasalt = new SeaSalt;
let original = 'test';
let ciphertext = seasalt.encrypt(
	original, 
	'a3a44974a290878ad341befe2b96dc561d7692e02ab39c7bef26c67f37a5f46e', 
	'xchacha'
);
let decrypted = seasalt.decrypt(
	ciphertext, 
	'a3a44974a290878ad341befe2b96dc561d7692e02ab39c7bef26c67f37a5f46e', 
	'xchacha'
);
```

#### Password Hashing

Supports Argon2 and SCrypt.

```js
let seasalt = new SeaSalt;
let password = 'test'
let hash = seasalt.pwhash_create(password, 'normal', 'argon2');
let verify = seasalt.pwhash_verify(hash, password);
```

#### String Hashing

Supports SHA256 and SHA512.

```js
let seasate = new SeaSalt;
let string = 'test'
let hash = seasalt.sha256(string);
```

## Setting Defaults

You can set the encryption key in advanced by passing it along at runtime:

```js
let seasalt = new SeaSalt({
    algorithm: 'xchacha',
    secret: 'changeme3xg4#',
    pwhash: 'argon2'
});
```

## Notes

Libsodium supports more than just XChaCha20-Poly1305; however, the Javascript library does not support AES-256-GCM.