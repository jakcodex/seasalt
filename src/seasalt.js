/*
 Seasalt Libsodium Wrapper
 */

class SeaSalt {

    constructor(config) {

        this.version = {
            major: 0,
            minor: 2
        };

        this.config = {
            algorithm: 'xchacha',
            secret: 'changeme3xg4#',
            pwhash: 'argon2'
        };

        this.state = {
            ready: false,
            aead: false
        };

        //  it must be one of these

        if ( ['argon2', 'scrypt'].indexOf(this.config.pwhash) === -1 ) this.config.pwhash = 'argon2';

        //  merge configurations
        $.extend(true, this.config, config);
        if ( typeof this.config.logger === 'undefined' ) this.config.logger = console.log;

        //  link classes
        this.pwhash = {};
        this.pwhash.argon2 = new SeaSalt_PWHash_Argon2;
        this.pwhash.scrypt = new SeaSalt_PWHash_SCrypt;
        this.tools = new SeaSalt_Tools(this.config);

        this.aead = {};
        this.aead.xchacha = new SeaSalt_AEAD_XChaCha(this.config);

        this.hash = new SeaSalt_Hashing;

        //  check if jquery is available
        if ( typeof $ === 'undefined' ) {

           return {};

        }

        if ( sodium ) {
            this.config.logger('SeaSalt - Loaded successfully');
            this.state.ready = true;
            this.state.aead = this.aead_test();
            return this;
        } else {
            console.error('SeaSalt - Libsodium was not found');
        }

    }

    //  encrypt the data with the requested algorithm
    encrypt(string, secret, box) {

        if ( !string ) {
            console.error('SeaSalt.encrypt() requires a string or object to encrypt');
            return;
        }

        if ( !secret ) secret = this.config.secret;
        if ( typeof this.aead[this.config.algorithm] === 'object' ) {

            return this.aead[this.config.algorithm].encrypt(string, secret, box);

        } else {

            console.error('SeaSalt.encrypt() received invalid algorithm - ' + this.config.algorithm);

        }

    }

    decrypt(string, secret, box) {

        if ( !string ) {
            console.error('SeaSalt.aead.decrypt() requires a string to decrypt');
            return;
        }

        if ( !secret ) secret = this.config.secret;
        if ( typeof this.aead[this.config.algorithm] === 'object' ) {

            return this.aead[this.config.algorithm].decrypt(string, secret, box);

        } else {

            console.error('SeaSalt.aead.decrypt() received invalid algorithm - ' + this.config.algorithm);

        }

    };

    pwhash_create(password, security, algorithm) {

        if ( !algorithm ) algorithm = this.config.pwhash;
        if ( algorithm && Object.keys(this.pwhash).indexOf(algorithm) === -1 ) algorithm = this.config.pwhash;
        return this.pwhash[algorithm].create(password, security);

    }

    pwhash_verify(hash, password, algorithm) {

        if ( !algorithm ) algorithm = this.config.pwhash;
        if ( algorithm && Object.keys(this.pwhash).indexOf(algorithm) === -1 ) algorithm = this.config.pwhash;
        return this.pwhash[algorithm].verify(hash, password);

    }

    //  test if sodium is working
    test() {

        let result = sodium.to_hex(sodium.crypto_generichash(64, 'test'));
        return ( result === 'a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572' );

    }

    //  test if aead is working
    aead_test() {

        let original = 'test';
        let ciphertext = this.encrypt(original);
        let result = this.decrypt(ciphertext);
        return ( original === result);

    }

    //  create a secret aead box
    box_create(userPassword, secretItem) {

        //  requires aead support
        if ( this.state.aead === false ) return;

        //  enforce any minimum password strength
        if ( this.tools.passwordStrength(userPassword) < this.config.minimumStrength ) return;

        //  parse the box contents into a string
        if ( typeof secretItem === 'boolean' ) secretItem = ( secretItem === false ) ? "false" : "true";
        if ( typeof secretItem === 'number' ) secretItem = secretItem.toString();
        if ( typeof secretItem === 'object' ) secretItem = JSON.stringify(secretItem, true, 5);
        if ( typeof secretItem === 'undefined' ) secretItem = this.aead[this.config.algorithm].key();
        if ( typeof secretItem !== 'string' ) return false;

        //  wrap the box
        let box = this.encrypt(secretItem, userPassword);

        //  verify the box
        let contents = this.decrypt(box, userPassword);
        if ( contents !== secretItem ) {
            this.config.logger('SeaSalt/AEAD/box_create - Failed to validate box contents');
            return false;
        }

        //  return the box
        return box;

    }

    //  repackage a box
    box_repackage(box, userPassword, newPassword) {

        //  enforce any minimum password strength
        if ( this.tools.passwordStrength(newPassword) < this.config.minimumStrength ) return;

        //  open the box
        let contents = this.decrypt(box, userPassword);

        //  return the original box if we failed to open it
        if ( typeof contents !== 'string' ) return box;

        //  repackage the contents and return the new box
        return this.box_create(newPassword, contents);

    }

    //  check if a secret item matches the contents of a box
    box_check(box, userPassword, secretItem) {

        if ( this.state.aead === false ) return;
        if ( typeof secretItem === 'boolean' ) secretItem = ( secretItem === false ) ? "false" : "true";
        if ( typeof secretItem === 'number' ) secretItem = secretItem.toString();
        if ( typeof secretItem === 'object' ) secretItem = JSON.stringify(secretItem, true, 5);
        if ( typeof secretItem !== 'string' ) return false;

        let contents = this.decrypt(box, userPassword);
        return ( contents === secretItem );

    }

}

/* Generic Hashing */

class SeaSalt_Hashing {

    sha256(string, format) {

        if ( !format ) format = 'hex';
        if ( ['ascii', 'hex', 'binary', 'base64'].indexOf(format) === -1 ) format = 'hex';
        let result = sodium.crypto_hash_sha256(string);
        if ( format === 'hex' ) return sodium.to_hex(result);
        if ( format === 'base64' ) return sodium.to_base64(result);
        return result;

    }

    sha512(string, format) {

        if ( !format ) format = 'hex';
        if ( ['ascii', 'hex', 'binary', 'base64'].indexOf(format) === -1 ) format = 'hex';
        let result = sodium.crypto_hash_sha512(string);
        if ( format === 'hex' ) return sodium.to_hex(result);
        if ( format === 'base64' ) return sodium.to_base64(result);
        return result;

    }

}

/* PWHash Classes */

//
//  Argon2 Password Hashing
//
class SeaSalt_PWHash_Argon2 {

    create(password, security) {

        let opsLimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;

        if ( !security ) security = 'normal';
        if ( ['light', 'normal', 'moderate', 'high'].indexOf(security) === -1 ) security = 'normal';
        if ( security === 'normal' ) {

            opsLimit = opsLimit*2;

        } else if ( security === 'moderate' ) {

            opsLimit = opsLimit*4;

        } else if ( security === 'high' ) {

            opsLimit = opsLimit*6;

        }

        return sodium.crypto_pwhash_str(password, opsLimit, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE);

    }

    verify(hash, password) {

        return sodium.crypto_pwhash_str_verify(hash, password);

    }

}

//
//  SCrypt Password Hashing
//
class SeaSalt_PWHash_SCrypt {

    create(password, security) {

        let opsLimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE;
        let memLimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE;

        if ( !security ) security = 'normal';
        if ( ['light', 'normal', 'moderate', 'high'].indexOf(security) === -1 ) security = 'normal';
        if ( security === 'normal' ) {

            opsLimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE*3;

        } else if ( security === 'moderate' ) {

            opsLimit = (sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE+sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE)*0.25;

        } else if ( security === 'high' ) {

            opsLimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE;

        }

        let result = sodium.crypto_pwhash_scryptsalsa208sha256_str(password, opsLimit, memLimit);
        sodium.memzero(password);
        return result;

    }

    verify(hash, password) {

        let result = sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(hash, password);
        sodium.memzero(password);
        return result;

    }

}

/* AEAD Classes */

//
//  XChaCha20-Poly1305-IETF AEAD Methods
//
class SeaSalt_AEAD_XChaCha {

    constructor(config) {

        this.config = {
            minimumEntropy: 1,
            minimumKeyLength: 1,
            minimumStrength: 0
        };
        if ( typeof config === 'object' ) $.extend(true, this.config, config);

        this.hash = new SeaSalt_Hashing;
        this.tools = new SeaSalt_Tools;

    }

    encrypt(string, secret, box) {

        if ( !string || !secret ) {
            console.error('SeaSalt.aead.xchacha.encrypt() requires a string or secret to encrypt');
            return;
        }

        //  open a box to object the secret key
        if ( typeof box === 'string' ) {

            let contents = this.decrypt(box, secret);
            if ( typeof contents === 'string' ) {

                secret = contents;
                this.config.logger('SeaSalt/AEAD/Encrypt - using secret box');

            }

        }

        let nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        let key = sodium.from_hex(this.hash.sha256(secret));
        let ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(string, '', '', nonce, key);
        sodium.memzero(key);
        return sodium.to_hex(nonce) + sodium.to_hex(ciphertext);

    };

    decrypt(string, secret, box) {

        if ( !string ) {
            console.error('SeaSalt.aead.decrypt() requires a string to decrypt');
            return;
        }

        //  open a box to object the secret key
        if ( typeof box === 'string' ) {

            let contents = this.decrypt(box, secret);
            if ( typeof contents === 'string' ) {

                secret = contents;
                this.config.logger('SeaSalt/AEAD/Decrypt - using secret box');

            }

        }

        let nonce = sodium.from_hex(string.substr(0, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES*2));
        let ciphertext = sodium.from_hex(string.substr(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES*2, string.length));
        let key = sodium.from_hex(this.hash.sha256(secret));
        let result = '';
        try {
            result = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt('', ciphertext, '', nonce, key);
        } catch (e) {}
        sodium.memzero(key);
        return ( result ) ? sodium.to_string(result) : undefined;

    };

    //  generate a random key
    key() {

        return sodium.to_hex(sodium.crypto_aead_xchacha20poly1305_ietf_keygen());

    }

}

/* SeaSalt Tools */
class SeaSalt_Tools {

    constructor(config) {

        this.config = {
            minimumEntropy: 6,
            minimumKeyLength: 6,
            minimumStrength: 1
        };
        if ( typeof config === 'object' ) $.extend(true, this.config, config);

    }

    passwordStrength(password) {

        //  check password strength
        let strength = 0;
        let cat = 0;
        let matches = {};

        //  lowercase alpha chars
        if ( matches.alpha = password.match(/[a-z]/g) ) strength++;

        //  uppercase alpha chars
        if ( matches.caps = password.match(/[A-Z]/g) ) strength++;

        //  numeric chars
        if ( matches.numeric = password.match(/[0-9]/g) ) strength++;

        //  symbol chars
        if ( matches.symbol = password.match(/[-!$%^&*()_+|~=`{}\[\]:#";'@<>?,.\/]/g) ) strength++;

        //  calculate entropy
        cat = strength;
        let chars = [];
        for ( let i in matches )
        if ( matches.hasOwnProperty(i) )
        if ( typeof matches[i] === 'object' && matches[i] !== null && matches[i].length )
        for ( let x = 0; x < matches[i].length; x++ )
        if ( chars.indexOf(matches[i][x].toLowerCase()) === -1 ) chars.push(matches[i][x].toLowerCase());

        //  adjust strength calculation

        //  supplied chars meeting minimum entropy are given a bonus
        if ( chars.length >= this.config.minimumEntropy ) strength = strength++;

        //  supplied chars below minimum entropy are heavily penalized
        if ( chars.length < this.config.minimumEntropy ) strength = strength-3;

        //  weak strength but extremely long is given a bonus
        if ( strength === 1 && password.length >= (this.config.minimumKeyLength*2) ) strength++;

        //  short passwords are penalized
        if ( password.length < (this.config.minimumKeyLength+4) ) strength--;

        //  only one type of charset is penalized
        if ( cat === 1 ) strength--;

        //  passwords shorter than the minimum length are invalid
        if ( password.length < this.config.minimumKeyLength ) strength = 0;

        //  return strength out of a maximum of 4
        if ( strength < 0 ) strength = 0;
        if ( strength > 4 ) strength = 4;
        return strength;

    };

}

//  AES-256-GCM not supported in browser library