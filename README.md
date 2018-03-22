# SeaSalt

![SeaSalt](https://img.shields.io/badge/dynamic/json.svg?label=Seasalt&colorB=9e43f9&prefix=v&suffix=&query=$.version&uri=https%3A%2F%2Fjakcodex.github.io%2Fseasalt%2Fpackage.json)

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

//  or

let aead = new SeaSalt_AEAD_XChacha;
let original = 'test';
let ciphertext = aead.encrypt(
    original,
    'a3a44974a290878ad341befe2b96dc561d7692e02ab39c7bef26c67f37a5f46e'
);
let decrypted = aead.decrypt(
    ciphertext,
    'a3a44974a290878ad341befe2b96dc561d7692e02ab39c7bef26c67f37a5f46e'
);

//  or

let original = 'test';
let k1 = new SeaSalt_AEAD_XChacha(
    test,
    'a3a44974a290878ad341befe2b96dc561d7692e02ab39c7bef26c67f37a5f46e'
);
let decrypted = k1.decrypt(
    k1.ciphertext,
    'a3a44974a290878ad341befe2b96dc561d7692e02ab39c7bef26c67f37a5f46e'
);
```

#### AEAD Secret Box

Create a box with a secret item that can be repackaged and used in encryption and decryption.

Attempts to convert any supplied secret item to text. If no item is provided it generates a random secret key.

When used in AEAD encryption, the secret box is secured with the user's password and contains the actual encryption key used on data.

```js
let seasalt = new SeaSalt;
let userPassword = 'this is an AMAZING! password :) 4';
let box = new SeaSalt_AEAD_SecretBox(userPassword);
let k1 = new SeaSalt_AEAD_XChacha('My secret message', userPassword, box);
let decrypted = k1.decrypt(
    k1.ciphertext,
    userPassword
);
```

Changing the user password on a box is easy. If repackaging fails, the original box is returned.

```js
let newPassword = 'IKShkhsfh(@#08us0dSklhgfdksghbf3';
let newbox = (new SeaSalt).box_repackage(box, userPassword, newPassword);
let decrypted2 = k1.decrypt(
    k1.ciphertext,
    newPassword,
    newbox
);
```

#### Test Password Strength

Test the strength of a supplied password against basic user-defined requirements.

```js
let seasalt = new SeaSalt({
    minimumEntropy: 8,
    minimumKeyLength: 8,
    minimumStrength: 2
});
strength = seasalt.tools.passwordStrength('test8885'); // returns 0
strength = seasalt.tools.passwordStrength('testapple8885'); // returns 2
strength = seasalt.tools.passwordStrength('testApple8885'); // returns 3
strength = seasalt.tools.passwordStrength('testApp!e8885'); // returns 4

//  or

let tools = new SeaSalt_Tools({
    minimumEntropy: 8,
    minimumKeyLength: 8,
    minimumStrength: 2
});
strength = tools.passwordStrength('test8885'); // returns 0
strength = tools.passwordStrength('testapple8885'); // returns 2
strength = tools.passwordStrength('testApple8885'); // returns 3
strength = tools.passwordStrength('testApp!e8885'); // returns 4
```

#### Password Hashing

Supports Argon2 and SCrypt.

```js
let seasalt = new SeaSalt;
let password = 'test'
let hash = seasalt.pwhash_create(password, 'normal', 'argon2');
let verify = seasalt.pwhash_verify(hash, password);

//  or

let pwhash = new SeaSalt_PWHash_Argon2;
let password = 'test';
let hash = pwhash.create(password);
let verify = pwhash.verify(hash, password);

//  or

let pwhash = new SeaSalt_PWHash_SCrypt;
/*...*/
```

#### String Hashing

Supports SHA256 and SHA512.

```js
let seasate = new SeaSalt;
let string = 'test'
let hash = seasalt.hash.sha256(string);

//  or

let tools = new SeaSalt_Hashing;
let string = 'test';
let hash = tools.sha256(string);

//  or

let string = 'test';
let hash = new SeaSalt_Hashing(string, 'sha512');
```

## Setting Defaults

You can set the encryption key in advanced by passing it along at runtime:

```js
let seasalt = new SeaSalt({
    algorithm: 'xchacha',
    secret: 'changeme3xg4#',
    pwhash: 'argon2',
    minimumEntropy: 1,
    minimumKeyLength: 1,
    minimumStrength: 0
});
```

## Notes

Libsodium supports more than just XChaCha20-Poly1305; however, the Javascript library does not support AES-256-GCM.
