/*
 Seasalt Libsodium Wrapper
 */

class SeaSalt {

    constructor(config) {

        this.version = {
            major: 0,
            minor: 1
        };

        this.config = {
            algorithm: 'xchacha',
            passphrase: 'changeme3xg4#'
        };

        this.state = {
            ready: false,
            aead: false
        };

        this.aead = {};
        this.aead.xchacha = new SeaSalt_AEAD_XChaCha;

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

    //  encrypt a string using an aead cipher
    aead_encrypt(string, passphrase, algorithm) {

        if ( this.state.ready === false ) {
            console.error('SeaSalt.aead_encrypt() cannot execute if SeaSalt is not ready');
            return;
        }

        if ( !string ) {
            console.error('SeaSalt.aead_encrypt() requires a string or object to encrypt');
            return;
        }

        if ( !algorithm ) algorithm = this.config.algorithm;
        if ( !passphrase ) passphrase = this.config.passphrase;
        if ( typeof this.aead[algorithm] === 'object' ) {

            return this.aead[algorithm].encrypt(string, passphrase);

        } else {

            console.error('SeaSalt.aead_encrypt() received invalid algorithm - ' + algorithm);

        }

    }

    //  decrypt the supplied aead ciphertext
    aead_decrypt(string, passphrase, algorithm) {

        if ( this.state.ready === false ) {
            console.error('SeaSalt.aead_decrypt() cannot execute if SeaSalt is not ready');
            return;
        }

        if ( !string ) {
            console.error('SeaSalt.aead_decrypt() requires a string to decrypt');
            return;
        }

        if ( !algorithm ) algorithm = this.config.algorithm;
        if ( !passphrase ) passphrase = this.config.passphrase;
        if ( typeof this.aead[algorithm] === 'object' ) {

            return this.aead[algorithm].decrypt(string, passphrase);

        } else {

            console.error('SeaSalt.aead_decrypt() received invalid algorithm - ' + algorithm);

        }

    }

    //  test if sodium is working
    test() {

        let result = sodium.to_hex(sodium.crypto_generichash(64, 'test'));
        return ( result === 'a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572' );

    }

    //  test if aead is working
    aead_test() {

        let original = 'test';
        let ciphertext = this.aead_encrypt(original);
        let result = this.aead_decrypt(ciphertext);
        return ( original === result);

    }

}

//
//  XChaCha20-Poly1305-IETF AEAD Methods
//
class SeaSalt_AEAD_XChaCha {

    encrypt(string, passphrase) {

        if ( !string || !passphrase ) {
            console.error('SeaSalt.aead.xchacha.encrypt() requires a string or passphrase to encrypt');
            return;
        }

        let nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        let key = sodium.from_hex($.sha256(passphrase));
        let ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(string, '', '', nonce, key);
        return sodium.to_hex(nonce) + sodium.to_hex(ciphertext);

    };

    decrypt(string, passphrase) {

        if ( !string ) {
            console.error('SeaSalt.aead_decrypt() requires a string to decrypt');
            return;
        }


        let nonce = sodium.from_hex(string.substr(0, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES*2));
        let ciphertext = sodium.from_hex(string.substr(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES*2, string.length));
        let key = sodium.from_hex($.sha256(passphrase));
        let result = '';
        try {
            result = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt('', ciphertext, '', nonce, key);
        } catch (e) {}
        return ( result ) ? sodium.to_string(result) : undefined;

    };

    key() {

        return sodium.to_hex(sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES));

    }

}