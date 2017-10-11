# SeaSalt

A simple Javascript class making Libsodium easier to use.

See it in action here: <a href="https://jakcodex.github.io/seasalt/seasalt.html">https://jakcodex.github.io/seasalt/seasalt.html</a>

## Example

```js
let seasalt = new SeaSalt;

let original = 'Text to encrypt';
let ciphertext = seasalt.aead_encrypt(
	original, 
	'myPassphrase', 
	'xchacha'
);

let decrypted = seasalt.aead_decrypt(
	ciphertext, 
	'myPassphrase', 
	'xchacha'
);
```

## Setting Defaults

You can set the encryption key in advanced by passing it along at runtime:

```js
let seasalt = new SeaSalt({passphrase: 'myPassphrase'});
```

## Notes

Libsodium supports more than just XChaCha20-Poly1305; however, the Javascript library does not support AES-256-GCM.