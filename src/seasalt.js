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

        //  link classes
        this.pwhash = {};
        this.pwhash.argon2 = new SeaSalt_PWHash_Argon2;
        this.pwhash.scrypt = new SeaSalt_PWHash_SCrypt;

        this.aead = {};
        this.aead.xchacha = new SeaSalt_AEAD_XChaCha;

        this.hash = new SeaSalt_Hashing;

        //  check if jquery is available
        if ( typeof $ === 'undefined' ) {

           return {};

        }

        //  merge configurations
        $.extend(true, this.config, config);

        if ( sodium ) {
            console.info('SeaSalt - Loaded successfully');
            this.state.ready = true;
            this.state.aead = this.aead_test();
            return this;
        } else {
            console.error('SeaSalt - Libsodium was not found');
        }

    }

    //  encrypt the data with the requested algorithm
    encrypt(string, secret, algorithm) {

        if ( !string ) {
            console.error('SeaSalt.encrypt() requires a string or object to encrypt');
            return;
        }

        if ( !algorithm ) algorithm = this.config.algorithm;
        if ( !secret ) secret = this.config.secret;
        if ( typeof this.aead[algorithm] === 'object' ) {

            return this.aead[algorithm].encrypt(string, secret);

        } else {

            console.error('SeaSalt.encrypt() received invalid algorithm - ' + algorithm);

        }

    }

    decrypt(string, secret, algorithm) {

        if ( !string ) {
            console.error('SeaSalt.aead.decrypt() requires a string to decrypt');
            return;
        }

        if ( !algorithm ) algorithm = this.config.algorithm;
        if ( !secret ) secret = this.config.secret;
        if ( typeof this.aead[algorithm] === 'object' ) {

            return this.aead[algorithm].decrypt(string, secret);

        } else {

            console.error('SeaSalt.aead.decrypt() received invalid algorithm - ' + algorithm);

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

class SeaSalt_PWHash_Argon2 {

    /*
     crypto_pwhash_OPSLIMIT_INTERACTIVE = 32Mb
     crypto_pwhash_OPSLIMIT_MODERATE = 128Mb / 0.7s
     crypto_pwhash_OPSLIMIT_SENSITIVE = 512Mb / 3.5s
    */
    create(password, security) {

        let opsLimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
        let memLimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;

        if ( !security ) security = 'normal';
        if ( ['light', 'normal', 'moderate', 'high'].indexOf(security) === -1 ) security = 'normal';
        if ( security === 'normal' ) {

            opsLimit = opsLimit*2;

        } else if ( security === 'moderate' ) {

            opsLimit = opsLimit*4;

        } else if ( security === 'high' ) {

            opsLimit = opsLimit*6;

        }

        console.log(opsLimit, memLimit);
        return sodium.crypto_pwhash_str(password, opsLimit, memLimit);

    }

    verify(hash, password) {

        return sodium.crypto_pwhash_str_verify(hash, password);

    }

}

class SeaSalt_PWHash_SCrypt {

    /*
     crypto_pwhash_OPSLIMIT_INTERACTIVE = 32Mb
     crypto_pwhash_OPSLIMIT_MODERATE = 128Mb / 0.7s
     crypto_pwhash_OPSLIMIT_SENSITIVE = 512Mb / 3.5s
     */
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

        console.log(opsLimit);
        return sodium.crypto_pwhash_scryptsalsa208sha256_str(password, opsLimit, memLimit);

    }

    verify(hash, password) {

        return sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(hash, password);

    }

}

/* AEAD Classes */

//
//  XChaCha20-Poly1305-IETF AEAD Methods
//
class SeaSalt_AEAD_XChaCha {

    encrypt(string, secret) {

        if ( !string || !secret ) {
            console.error('SeaSalt.aead.xchacha.encrypt() requires a string or secret to encrypt');
            return;
        }

        let nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        let key = sodium.from_hex($.sha256(secret));
        let ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(string, '', '', nonce, key);
        sodium.memzero(key);
        return sodium.to_hex(nonce) + sodium.to_hex(ciphertext);

    };

    decrypt(string, secret) {

        if ( !string ) {
            console.error('SeaSalt.aead.decrypt() requires a string to decrypt');
            return;
        }


        let nonce = sodium.from_hex(string.substr(0, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES*2));
        let ciphertext = sodium.from_hex(string.substr(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES*2, string.length));
        let key = sodium.from_hex($.sha256(secret));
        let result = '';
        try {
            result = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt('', ciphertext, '', nonce, key);
        } catch (e) {}
        sodium.memzero(key);
        return ( result ) ? sodium.to_string(result) : undefined;

    };

    key() {

        return sodium.to_hex(sodium.crypto_aead_xchacha20poly1305_ietf_keygen());

    }

}

//  AES-256-GCM not supported in browser library