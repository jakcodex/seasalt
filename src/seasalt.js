/**
 * @file
 * ## __Seasalt Libsodium.js Wrapper__
 *
 * A collection of tools that enable easy encryption and storage in the browser utilizing Libsodium.
 *
 * ### Classes
 *
 * ###### __{@link SeaSalt_Common SeaSalt / SeaSalt_Common}__
 * A basic interface for accessing the various tools within SeaSalt. Only good for general use when dedicated class instances aren't necessary.
 *
 * ###### __{@link SeaSalt_AEAD_SecretBox}__
 * Create and manage a secret box that contains an encryption key, message, JSON string, or other data.
 *
 * ###### __{@link SeaSalt_AEAD_XChaCha}__
 * Encrypt and decrypt strings with XChaCha20-Poly1305 AEAD encryption with optional secret box.
 *
 * ###### __{@link SeaSalt_Hashing}__
 * Hash strings using SHA256 or SHA512 and output in hex, base64, or binary.
 *
 * ###### __{@link SeaSalt_Keychain}__
 * Keychain management for storing and using encryption keys and providing a fully encrypted localStorage api.
 *
 * ###### __{@link SeaSalt_PWHash_Argon2}__
 * Password hashing and validation using the Argon2 library.
 *
 * ###### __{@link SeaSalt_PWHash_SCrypt}__
 * Password hashing and validation using the SCrypt library.
 *
 * ###### __{@link SeaSalt_Tools}__
 * Handy tools and gadgets.
 *
 * @version 0.2
 * @author Jakcodex / Jakisaurus
 * @see {@link https://github.com/jakcodex/seasalt GitHub}
 * @see {@link https://github.com/jedisct1/libsodium.js Libsodium.js}
 */

/**
 * @class SeaSalt Common Class
 * @description Provides a single object with properties leading to each available class. For general use only when directly using the class isn't necessary.
 * @property {object} config
 * @property {number} [config.minimumEntropy=1] - Minimum password entropy required
 * @property {number} [config.minimumKeyLength=1] - Minimum password character length
 * @property {number} [config.minimumStrength=0] - Minimum password strength
 * @property {function} [config.logger=config.log] - Logging handler
 * @property {string} config.secret - Default encryption password for encrypting and decrypting strings
 * @property {string} [config.pwhash=argon2] - Default password hashing class
 * @property {string} [config.pwsecurity=normal] - Default password hashing strength
 * @property {object} aead
 * @property {SeaSalt_AEAD_XChaCha} aead.xchacha - An instance of {@link SeaSalt_AEAD_XChaCha}
 * @property {SeaSalt_Hashing} hash - An instance of {@link SeaSalt_Hashing}
 * @property {object} pwhash
 * @property {SeaSalt_PWHash_Argon2} pwhash.argon2 - An instance of {@link SeaSalt_PWHash_Argon2}
 * @property {SeaSalt_PWHash_Argon2} pwhash.scrypt - An instance of {@link SeaSalt_PWHash_SCrypt}
 * @property {SeaSalt_AEAD_SecretBox} secretbox - An instance of {@link SeaSalt_AEAD_SecretBox}
 * @property {SeaSalt_Tools} tools - An instance of {@link SeaSalt_Tools}
 * @example <caption>Basic Usage</caption>
 * //  most basic usage
 * let seasalt = new SeaSalt();
 *
 * //  or include a config
 * let seasalt = new SeaSalt({
 *     minimumKeyLength: 12
 * });
 */
class SeaSalt_Common {

    /**
     * @constructor
     * @param {object} [config] - User configuration
     */
    constructor(config) {

        this.version = {
            major: 0,
            minor: 2
        };

        this.config = {
            algorithm: 'xchacha',
            secret: 'changeme3xg4#',
            pwhash: 'argon2',
            pwsecurity: 'normal'
        };

        this.state = {
            ready: false,
            aead: false
        };

        //  it must be one of these

        if ( ['argon2', 'scrypt'].indexOf(this.config.pwhash) === -1 ) this.config.pwhash = 'argon2';

        //  merge configurations
        if ( typeof config === 'object' )
            for ( let i in config )
                if ( config.hasOwnProperty(i) )
                    this.config[i] = config[i];
        if ( typeof this.config.logger === 'undefined' ) this.config.logger = console.log;

        //  link classes
        this.pwhash = {};
        this.pwhash.argon2 = new SeaSalt_PWHash_Argon2;
        this.pwhash.scrypt = new SeaSalt_PWHash_SCrypt;
        this.tools = new SeaSalt_Tools(this.config);
        this.secretbox = new SeaSalt_AEAD_SecretBox(this.config);

        this.aead = {};
        this.aead.xchacha = new SeaSalt_AEAD_XChaCha(this.config);

        this.hash = new SeaSalt_Hashing;

        if ( sodium ) {
            this.config.logger('SeaSalt - Loaded successfully');
            this.state.ready = true;
            this.state.aead = this.aead_test();
        } else {
            console.error('SeaSalt - Libsodium was not found');
        }

    }

    /**
     * @function
     * @param {string} string - String to encrypt
     * @param {string} [secret=config.password] - Password to use for encryption
     * @param {string} [box] - Secret box to utilize
     * @returns {string} Returns the encrypted ciphertext.
     * @description Encrypts supplied string with a known or provided password and optionally a secret box.
     */
    //  encrypt the data with the requested algorithm
    encrypt(string, secret, box) {

        if ( !string ) throw 'SeaSalt.encrypt() requires a string or object to encrypt';
        if ( !secret ) secret = this.config.secret;
        if ( !secret ) throw 'SeaSalt.encrypt() could not find a password to use';
        if ( typeof this.aead[this.config.algorithm] === 'object' ) {
            return this.aead[this.config.algorithm].encrypt(string, secret, box);
        } else throw 'SeaSalt.encrypt() received invalid algorithm - ' + this.config.algorithm;

    }

    /**
     * @function
     * @param {string} string - String to encrypt
     * @param {string} [secret=config.password] - Password to use for encryption
     * @param {string} [box] - Secret box to utilize
     * @returns {string} Returns the decrypted plaintext.
     * @description Decrypts supplied ciphertext with a known or provided password and optionally a secret box.
     */
    decrypt(string, secret, box) {

        if ( !string ) throw 'SeaSalt.decrypt() requires a string to decrypt';
        if ( !secret ) secret = this.config.secret;
        if ( !secret ) throw 'SeaSalt.decrypt() could not find a password to use';
        if ( typeof this.aead[this.config.algorithm] === 'object' ) {
            return this.aead[this.config.algorithm].decrypt(string, secret, box);
        } else throw 'SeaSalt.decrypt() received invalid algorithm - ' + this.config.algorithm;

    };

    /**
     * @function
     * @param {string} password - Password to hash
     * @param {string} [security=config.pwsecurity] - Hashing strength
     * @param {string} [algorithm=config.pwhash] - Hashing algorithm
     * @returns {string} Returns the password hash.
     * @description Create a strong password hash using Argon2 or SCrypt.
     */
    pwhash_create(password, security, algorithm) {

        if ( !algorithm ) algorithm = this.config.pwhash;
        if ( algorithm && Object.keys(this.pwhash).indexOf(algorithm) === -1 ) algorithm = this.config.pwhash;
        return this.pwhash[algorithm].create(password, security);

    }

    /**
     * @function
     * @param {string} hash - Password hash to test against
     * @param {string} password - Password to test
     * @param {string} [algorithm=config.pwhash] - Hashing algorithm
     * @returns {boolean} Returns true or false.
     * @description Checks a password against a password hash to check for validity using Argon2 or SCrypt.
     */
    pwhash_verify(hash, password, algorithm) {

        if ( !algorithm ) algorithm = this.config.pwhash;
        if ( algorithm && Object.keys(this.pwhash).indexOf(algorithm) === -1 ) algorithm = this.config.pwhash;
        return this.pwhash[algorithm].verify(hash, password);

    }

    /**
     * @function
     * @returns {boolean} Returns true or false.
     * @description Test whether or not Sodium is functioning.
     */
    test() {

        let result = sodium.to_hex(sodium.crypto_generichash(64, 'test'));
        return ( result === 'a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572' );

    }

    /**
     * @function
     * @returns {boolean} Returns true or false.
     * @description Test whether or not AEAD encryption is functioning.
     */
    aead_test() {

        let original = 'test';
        let ciphertext = this.encrypt(original);
        let result = this.decrypt(ciphertext);
        return ( original === result);

    }

}

/**
 * @class SeaSalt
 * @description An alias for {@link SeaSalt_Common}
 */
class SeaSalt extends SeaSalt_Common {}

/**
 * @class String Hashing Utilities
 * @description Requires the Sodium Sumo distribution
 */
class SeaSalt_Hashing {

    /**
     * @constructor
     * @param {string} [string] - String to hash
     * @param {string} [hash] - Hashing algorithm to use
     * @param {string} [format] - Output format of the hash data (hex, binary, base64)
     * @property {binary} binary - Binary result of hashed string
     * @property {string} hex - Hex result of hashed string
     * @property {string} base64 - Base64 result of hashed string
     * @property {number} length - Length of requested format result
     */
    constructor(string, hash, format) {

        this.reservedProperties = ['constructor', 'toString'];
        this.validFormats = ['hex', 'binary', 'base64'];
        if ( typeof string === 'string' ) {

            let props = Object.getOwnPropertyNames(Object.getPrototypeOf(new SeaSalt_Hashing));
            for ( let x = 0; x < this.reservedProperties.length; x++ )
                props.splice(props.indexOf(this.reservedProperties[x]), 1);
            props = JSON.parse(JSON.stringify(props));
            if ( typeof hash === 'undefined' ) hash = 'sha256';
            if ( this.validFormats.indexOf(format) === -1 ) format = 'hex';
            if ( props.indexOf(hash) === -1 ) throw "Invalid hash algorithm requested.";
            this.binary = this[hash](string, 'binary');
            this.hex = sodium.to_hex(this.binary);
            this.base64 = sodium.to_base64(this.binary);
            this.format = format;
            this.length = this[this.format].length;

        }

    }

    /**
     * @function
     * @returns {string}
     * @description Returns the hash result in hex format.
     */
    toString() {

        return this.hex;

    }

    /**
     * @function
     * @param {string} string - String to hash
     * @param {string} [format] - Output format of the hash data (hex, binary, base64)
     * @returns {binary | string} Returns in the requested format.
     * @example
     * let hash = new SeaSalt_Hashing();
     * hash.sha256('testing')
     *
     * //  returns a string like: cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90
     */
    sha256(string, format) {

        if ( !format ) format = 'hex';
        if ( this.validFormats.indexOf(format) === -1 ) format = 'hex';
        let result = sodium.crypto_hash_sha256(string);
        if ( format === 'hex' ) return sodium.to_hex(result);
        if ( format === 'base64' ) return sodium.to_base64(result);
        return result;

    }

    /**
     * @function
     * @param {string} string - String to hash
     * @param {string} [format] - Output format of the hash data (hex, binary, base64)
     * @returns {binary | string} Returns in the requested format.
     * @example
     * let hash = new SeaSalt_Hashing();
     * hash.sha512('testing')
     *
     * //  returns a string like: 521b9ccefbcd14d179e7a1bb877752870a6d620938b28a66a107eac6e6805b9d0989f45b5730508041aa5e710847d439ea74cd312c9355f1f2dae08d40e41d50
     */
    sha512(string, format) {

        if ( !format ) format = 'hex';
        if ( this.validFormats.indexOf(format) === -1 ) format = 'hex';
        let result = sodium.crypto_hash_sha512(string);
        if ( format === 'hex' ) return sodium.to_hex(result);
        if ( format === 'base64' ) return sodium.to_base64(result);
        return result;

    }

}

/* PWHash Classes */

/**
 * @class Argon2 Password Hashing
 * @description Requires the Sodium Sumo distribution
 */
class SeaSalt_PWHash_Argon2 {

    /**
     * @function
     * @param {string} password - Password to hash
     * @param {string} [security=normal] - Security level to hash with
     * @returns {string} Returns the Argon2 hash of the supplied password.
     * @description Creates a Argon2 hash of the provided password with optional security level.
     * @example
     * let argon2 = new SeaSalt_PWHash_Argon2();
     * argon2.create('myterriblepassword');
     *
     * //  returns the argon2 string like: $argon2id$v=19$m=65536,t=4,p=1$Vp+2jMiZyshaDgdVWDBRiQ$zOQo/pYHko7cZpKo9ptgBKGd4oJgCzOoRJa7FiPDRqA
     */
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

    /**
     * @function
     * @param {string} hash - Argon2 hash
     * @param {string} password - User password
     * @returns {boolean}
     * @description Verify if a password matches an Argon2 hash.
     * @example
     * //  using the example from argon2.{@link SeaSalt_PWHash_Argon2#create create}
     * let argon2 = new SeaSalt_PWHash_Argon2();
     * argon2.verify('$argon2id$v=19$m=65536,t=4,p=1$Vp+2jMiZyshaDgdVWDBRiQ$zOQo/pYHko7cZpKo9ptgBKGd4oJgCzOoRJa7FiPDRqA', 'myterriblepassword');
     */
    verify(hash, password) {

        return sodium.crypto_pwhash_str_verify(hash, password);

    }

}

/**
 * @class SCrypt Password Hashing
 * @description Requires the Sodium Sumo distribution
 */
class SeaSalt_PWHash_SCrypt {

    /**
     * @function
     * @param {string} password - Password to hash
     * @param {string} [security=normal] - Security level to hash with
     * @returns {string} Returns the SCrypt hash of the supplied password.
     * @description Creates a SCrypt hash of the provided password with optional security level.
     * @example
     * let scrypt = new SeaSalt_PWHash_SCrypt();
     * scrypt.create('myterriblepassword');
     *
     * //  returns the scrypt string like: $7$C6....1....HnSL7MLPJo3Q3aJLYzzfP96kaFajuaoBuohB1HDKJ97$01YB7VEvx4jw2GLUATR46n4M6Ng7CmK2eLVLs4j8ZSC
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

        let result = sodium.crypto_pwhash_scryptsalsa208sha256_str(password, opsLimit, memLimit);
        return result;

    }

    /**
     * @function
     * @param {string} hash - SCrypt hash
     * @param {string} password - User password
     * @returns {boolean}
     * @description Verify if a password matches an SCrypt hash.
     * @example
     * //  using the example from scrypt.{@link SeaSalt_PWHash_SCrypt#create create}
     * let scrypt = new SeaSalt_PWHash_SCrypt();
     * scrypt.verify('$7$C6....1....HnSL7MLPJo3Q3aJLYzzfP96kaFajuaoBuohB1HDKJ97$01YB7VEvx4jw2GLUATR46n4M6Ng7CmK2eLVLs4j8ZSC', 'myterriblepassword');
     */
    verify(hash, password) {

        return sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(hash, password);

    }

}

/* AEAD Classes */

class SeaSalt_AEAD_SecretBox {

    /**
     * @class AEAD Secret Box
     * @param {string} [userPassword] - Password for the secret box
     * @param {string} secretItem - Item to store inside the secret box
     * @param {object} [config] - User-provided Configuration data
     * @property {string} box - Secret box ciphertext once generated
     * @property {object} config - Configuration data
     * @property {number} [config.minimumEntropy=1] - Minimum password entropy required
     * @property {number} [config.minimumKeyLength=1] - Minimum password character length
     * @property {number} [config.minimumStrength=0] - Minimum password strength
     * @property {function} [config.logger=config.log] - Logging handler
     * @description Create a secret box to store information with a changeable password.
     *
     * At a basic level this is a glorified encrypted string.
     *
     * A typical usage for a secret box is to store an AEAD encryption key. The password on the secret box can change without requiring any encrypted data be re-encrypted.
     *
     * You can also store a JSON object with any data you want along with an encryption key.
     */
    constructor(userPassword, secretItem, config) {

        this.config = {
            minimumEntropy: 1,
            minimumKeyLength: 1,
            minimumStrength: 0,
            logger: console.log
        };
        if ( typeof userPassword === 'object' ) {

            config = userPassword;
            userPassword = undefined;
            secretItem = undefined;

        }

        if ( typeof config === 'object' )
            for ( let i in config )
                if ( config.hasOwnProperty(i) )
                    this.config[i] = config[i];

        this.hash = new SeaSalt_Hashing;
        this.tools = new SeaSalt_Tools(config);
        this.aead = new SeaSalt_AEAD_XChaCha(config);

        if ( userPassword ) this.box = this.create(userPassword, secretItem);

    }

    /**
     * @function
     * @returns {string}
     * @description Returns the secret box ciphertext.
     */
    toString() {
        return this.box;
    }

    //  create a secret aead box
    /**
     * @function
     * @param {string} userPassword - Password for the secret box
     * @param {string} secretItem - Item to place inside the box
     * @returns {string} Returns the secret box ciphertext.
     * @description Create a secret box with the provided item.
     * @example <caption>Basic Usage</caption>
     * let aead = new SeaSalt_AEAD_XChaCha();
     * let secretbox = new SeaSalt_AEAD_SecretBox();
     * secretbox.create('mygreatpassword1', aead.key());
     *
     * //  returns a string like: 077eb44fc4d04ad6093f6ab5c1938c151c07fd9fb360234670a7e0da4530aa3f...
     * @example <caption>Using a Secret Box with AEAD Encryption</caption>
     * let aead = new SeaSalt_AEAD_XChaCha();
     * let secretbox = new SeaSalt_AEAD_SecretBox();
     * secretbox.create('mygreatpassword1', aead.key());
     * let ciphertext = aead.encrypt('My great string', 'mygreatpassword1', secretbox);
     *
     * //  returns the encrypted ciphertext using the encryption key stored in the secret box
     */
    create(userPassword, secretItem) {

        //  return a box if it already exists
        if ( this.box ) return this.box;

        //  enforce any minimum password strength
        if ( this.tools.passwordStrength(userPassword) < this.config.minimumStrength ) throw "Supplied password does not meet the minimum strength requirements.";

        //  parse the box contents into a string
        if ( typeof secretItem === 'boolean' ) secretItem = ( secretItem === false ) ? "false" : "true";
        if ( typeof secretItem === 'number' ) secretItem = secretItem.toString();
        if ( typeof secretItem === 'object' ) secretItem = JSON.stringify(secretItem);
        if ( typeof secretItem === 'undefined' ) secretItem = this.aead.key();
        if ( typeof secretItem !== 'string' ) throw "Supplied secret item cannot be converted to a string.";

        //  wrap the box
        this.box = this.aead.encrypt(secretItem, userPassword);

        //  verify the box
        let contents = this.aead.decrypt(this.box, userPassword);
        if ( contents !== secretItem ) {
            this.config.logger('SeaSalt/AEAD/box_create - Failed to validate box contents');
            throw "Failed to validate the box contents.";
        }

        //  return the box
        return this.box;

    }

    /**
     * @function
     * @param {string} box - Secret box to repackage
     * @param {string} userPassword - Password of the existing secret box
     * @param {string} newPassword - New password to set on the secret box
     * @returns {string} Returns the secret box ciphertext.
     * @description Repackages a secret box and optionally changes its password.
     *
     * This will re-encrypt the contents of a secret box resulting in new secret box ciphertext.
     * @example
     * let secretbox = new SeaSalt_AEAD_SecretBox('mygreatpassword1', aead.key());
     *
     * //  repackage with same password
     * secretbox.repackage('mygreatpassword1');
     *
     * //  repackage with new password
     * secretbox.repackage('mygreatpassword1', 'evenbettarp4ssword');
     *
     * //  repackage with a supplied box
     * secretbox.repackage('077eb44fc4d04ad6093f6ab5c1938c151c07fd9fb360234670a7e0da4530aa3f...', 'mygreatpassword1');
     */
    repackage(box, userPassword, newPassword) {

        if ( !box && !this.box ) throw "Secret box must be provided for repackaging.";
        if ( box && userPassword && !newPassword ) {

            if ( !this.box ) throw "Secret box must be provided for repackaging.";
            newPassword = userPassword;
            userPassword = box;
            box = this.box;

        }

        if ( !box || !userPassword || !newPassword ) throw "Required arguments are missing";

        //  enforce any minimum password strength
        if ( this.tools.passwordStrength(newPassword) < this.config.minimumStrength ) return;

        //  open the box
        let contents = this.aead.decrypt(box, userPassword);

        //  return the original box if we failed to open it
        if ( typeof contents !== 'string' ) return box;

        //  repackage the contents and return the new box
        this.box = this.create(newPassword, contents);
        return this.box;

    }

    //  check if a secret item matches the contents of a box
    /**
     * @function
     * @param {string} box - Secret box to repackage
     * @param {string} userPassword - Password of the existing secret box
     * @param {string} [secretItem] - Item to check for inside the secret box
     * @returns {boolean} Returns true or false
     * @description Check if a secret box is valid and/or readable.
     * @example
     * //  using the result from the example in keychain.{@link SeaSalt_AEAD_SecretBox#create create}
     * let secretbox = new SeaSalt_AEAD_SecretBox();
     * secretbox.check('077eb44fc4d04ad6093f6ab5c1938c151c07fd9fb360234670a7e0da4530aa3f...', 'mygreatpassword1');
     *
     * //  result would return true or false
     */
    check(box, userPassword, secretItem) {

        if ( !box && !this.box ) throw "Secret box must be provided for checking.";
        if ( box && !userPassword ) {

            if ( !this.box ) throw "Secret box must be provided for repackaging.";
            userPassword = box;
            box = this.box;

        }

        if ( !box || !userPassword  ) throw "Required arguments are missing";

        if ( secretItem && typeof secretItem === 'boolean' ) secretItem = ( secretItem === false ) ? "false" : "true";
        if ( secretItem && typeof secretItem === 'number' ) secretItem = secretItem.toString();
        if ( secretItem && typeof secretItem === 'object' ) secretItem = JSON.stringify(secretItem, true, 5);
        if ( secretItem && typeof secretItem !== 'string' ) return false;

        let contents = this.aead.decrypt(box, userPassword);
        return (
            (
                secretItem &&
                contents === secretItem
            ) ||
            typeof contents === 'string'
        );

    }

}

class SeaSalt_AEAD_XChaCha {

    /**
     * @class XChaCha20-Poly1305-IETF AEAD Methods
     * @param {string} [string] - String to encrypt
     * @param {string} [secret] - Password to use for encryption
     * @param {string} [box] - Secret box to use with encryption
     * @param {string} [config] - Configuration data
     * @property {string} [box] - Secret box utilized in encryption
     * @property {string} [ciphertext] - Ciphertext generated by the most recent encryption request
     * @property {Object} config - AEAD Encryption Configuration
     * @property {number} [config.minimumEntropy=1] - Minimum password entropy required
     * @property {number} [config.minimumKeyLength=1] - Minimum password character length
     * @property {number} [config.minimumStrength=0] - Minimum password strength
     * @property {function} [config.logger=config.log] - Logging handler
     * @description AEAD Encryption
     * @example
     * let aead = new SeaSalt_AEAD_XChaCha('Hello world', 'mybestsecretevar33');
     *
     * //  ciphertext is stored in aead.ciphertext
     */
    constructor(string, secret, box, config) {

        if ( (typeof box === 'object' || typeof secret === 'object') && typeof config === 'undefined' ) {

            if ( typeof secret === 'object' ) {
                config = secret;
                secret = undefined;
                box = undefined;
            }

            if ( typeof box === 'object' && !(box instanceof SeaSalt_AEAD_SecretBox) ) {
                config = box;
                box = undefined;
            }

        }

        this.config = {
            minimumEntropy: 1,
            minimumKeyLength: 1,
            minimumStrength: 0,
            logger: console.log
        };

        if ( typeof string === 'object' ) {

            config = string;
            string = undefined;

        }

        if ( typeof config === 'object' )
            for ( let i in config )
                if ( config.hasOwnProperty(i) )
                    this.config[i] = config[i];

        this.hash = new SeaSalt_Hashing;
        this.tools = new SeaSalt_Tools;

        //  load any secretbox
        if ( box instanceof SeaSalt_AEAD_SecretBox && box.box ) this.box = box.box;
        if ( typeof box === 'string' ) this.box = box;

        //  run encryption if string is provided
        if ( typeof string === 'string' ) this.encrypt(string, secret, box);

    }

    /**
     * @function
     * @param {string} string - String to encrypt
     * @param {string} secret - Password to use for encryption
     * @param {SeaSalt_AEAD_SecretBox | string} [box] - Secret box ciphertext or instance
     * @returns {string} Returns the encrypted ciphertext
     * @description Encrypts a string optionally using a secret box.
     *
     * Each encryption has a unique nonce. The same string will never encrypt to the same ciphertext twice.
     *
     * Using a secret box allows you to let a user change passwords without needing to rewrite all encrypted data.
     *
     * See {@link SeaSalt_AEAD_SecretBox} for more information.
     * @example <caption>Basic Usage</caption>
     * let aead = new SeaSalt_AEAD_XChaCha();
     * aead.encrypt('Hello world', 'mybestsecretevar33');
     *
     * //  ciphertext in aead.ciphertext reads: 00002c4cdbf646c1bba6c3f543a104e78555069f3bf5ca09fc5b66c7201eca012d10f01cdf49c15654ec418f7cac0cd5a6b1d0
     * @example <caption>Secret Box Usage</caption>
     * //  this time we'll use a secret box
     * let secretbox = new {@link SeaSalt_AEAD_SecretBox}('mybestsecretevar33', aead.key());
     * aead.encrypt('Hello world', 'mybestsecretevar33', secretbox);
     *
     * //  the user password opens a secret box which contains the actual encryption key
     */
    encrypt(string, secret, box) {

        if ( !string || !secret ) throw 'SeaSalt_AEAD_XChaCha::encrypt requires a string or secret to encrypt';

        //  it's the box-box
        if ( typeof box === 'undefined' && this.box ) box = this.box;
        if ( box instanceof SeaSalt_AEAD_SecretBox && typeof box.box === 'string' ) {
            box = box.box;
        } else if ( box && typeof box !== 'string' ) throw 'SeaSalt_AEAD_XChacha::decrypt supplied SecretBox is invalid';

        //  open a box to obtain the secret key
        if ( typeof box === 'string' ) {

            this.box = box;
            let contents = this.decrypt(box, secret, false);
            if ( typeof contents === 'string' ) {

                //  box content can store additional data
                let object;
                try {
                    object = JSON.parse(contents);
                } catch(e) {}
                secret = ( typeof object === 'object' ) ? object.secret : contents;
                //this.config.logger('SeaSalt_AEAD_XChaCha::encrypt using secret box');

            } else throw "Failed to decrypt secret box.";

        }

        let nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        let key = sodium.from_hex(this.hash.sha256(secret));
        let ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(string, '', '', nonce, key);
        sodium.memzero(key);
        this.ciphertext = sodium.to_hex(nonce) + sodium.to_hex(ciphertext);
        return this.ciphertext;

    };

    /**
     * @function
     * @param {string} string - String to encrypt
     * @param {string} secret - Password to use for encryption
     * @param {SeaSalt_AEAD_SecretBox | string} [box] - Secret box ciphertext or instance
     * @returns {string} Returns the decrypted plaintext
     * @description Decrypts a string optionally using a secret box.
     *
     * Using a secret box allows you to let a user change passwords without needing to rewrite all encrypted data.
     *
     * See {@link SeaSalt_AEAD_SecretBox} for more information.
     * @example <caption>Basic Usage</caption>
     * //  using the result from the example at keychain.{@link SeaSalt_AEAD_XChaCha#encrypt encrypt}
     * let aead = new SeaSalt_AEAD_XChaCha();
     * aead.decrypt('00002c4cdbf646c1bba6c3f543a104e78555069f3bf5ca09fc5b66c7201eca012d10f01cdf49c15654ec418f7cac0cd5a6b1d0', 'mybestsecretevar33');
     *
     * //  returns a string like: Hello world
     * @example <caption>Secret Box Usage</caption>
     * //  this time we'll use a secret box
     * let secretbox = new {@link SeaSalt_AEAD_SecretBox}('mybestsecretevar33', aead.key());
     * aead.encrypt('Hello world', 'mybestsecretevar33', secretbox);
     *
     * //  the user password opens a secret box which contains the actual encryption key
     */
    decrypt(string, secret, box) {

        if ( !string || !secret ) {
            console.error('SeaSalt_AEAD_XChaCha::decrypt requires a string and secret to decrypt');
            return;
        }

        //  it's the box-box
        if ( typeof box === 'undefined' && this.box ) box = this.box;
        if ( box instanceof SeaSalt_AEAD_SecretBox && typeof box.box === 'string' ) {
            box = box.box;
        } else if ( box && typeof box !== 'string' ) {
            console.error('SeaSalt_AEAD_XChacha::decrypt supplied SecretBox is invalid');
            return;
        }

        //  open a box to obtain the secret key
        if ( typeof box === 'string' ) {

            this.box = box;
            let contents = this.decrypt(box, secret, false);
            if ( typeof contents === 'string' ) {

                //  box content can store additional data
                let object;
                try {
                    object = JSON.parse(contents);
                } catch(e) {}
                secret = ( typeof object === 'object' ) ? object.secret : contents;
                //this.config.logger('SeaSalt_AEAD_XChaCha::decrypt using secret box');

            } else throw "Failed to decrypt secret box.";

        }

        let nonce;
        let ciphertext;
        try {
            nonce = sodium.from_hex(string.substr(0, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES*2));
            ciphertext = sodium.from_hex(string.substr(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES*2, string.length));
        } catch (e) {
            return undefined;
        }
        let key = sodium.from_hex(this.hash.sha256(secret));
        let result = '';
        try {
            result = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt('', ciphertext, '', nonce, key);
        } catch (e) {}
        sodium.memzero(key);
        return ( result ) ? sodium.to_string(result) : undefined;

    };

    /**
     * @function
     * @returns {string}
     * @description Generates a unique AEAD encryption key in hex format.
     */
    key() {

        return sodium.to_hex(sodium.crypto_aead_xchacha20poly1305_ietf_keygen());

    }

    /**
     * @function
     * @returns {string}
     * @description Generate a JSON string containing encryption results
     */
    toJSON() {

        var data = {
            box: this.box,
            ciphertext: this.ciphertext
        };
        return JSON.stringify(data, true, 5);

    }

}

/**
 * @class SeaSalt Tools
 * @description A collection of commonly used tools
 */
class SeaSalt_Tools {

    /**
     * @constructor
     * @param {object} [config] - User-provided configuration data
     * @property {object} config - Configuration data
     * @property {number} [config.minimumEntropy=6] - Minimum password entropy required
     * @property {number} [config.minimumKeyLength=6] - Minimum password character length
     * @property {number} [config.minimumStrength=1] - Minimum password strength
     * @property {function} [config.logger=config.log] - Logging handler
     */
    constructor(config) {

        this.config = {
            minimumEntropy: 6,
            minimumKeyLength: 6,
            minimumStrength: 1
        };
        if ( typeof config === 'object' )
            for ( let i in config )
                if ( config.hasOwnProperty(i) )
                    this.config[i] = config[i];
        if ( typeof this.config.logger === 'undefined' ) this.config.logger = console.log;

    }

    /**
     * @function
     * @param {number} [length=32] - Length of string to generate
     * @param {boolean} [alpha=true] - Include lower case alphabet in the pool
     * @param {boolean} [caps=true] - Include upper case alphabet in the pool
     * @param {boolean} [numeric=true] - Include numbers in the pool
     * @param {boolean} [symbols=true] - Include symbols in the pool
     * @returns {string} Returns a random string from the character pool.
     * @description Generates a random string of any length with a variable character pool.
     */
    randomString(length, alpha, caps, numeric, symbols) {

        if ( typeof length !== 'number' ) length = 32;
        if ( typeof alpha !== 'boolean' ) alpha = true;
        if ( typeof caps !== 'boolean' ) caps = true;
        if ( typeof numeric !== 'boolean' ) numeric = true;
        if ( typeof symbols !== 'boolean' ) symbols = true;
        var pools = {
            alpha: 'abcdefghijklmnopqrstuvwxyz',
            caps: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            numeric: '0123456789',
            symbols: '[];\',./<>?:"{}\\|!@#$%^&*()-=_+`~'
        };

        var pool = '';
        if ( alpha === true ) pool = pool.concat(pools.alpha);
        if ( caps === true ) pool = pool.concat(pools.caps);
        if ( numeric === true ) pool = pool.concat(pools.numeric);
        if ( symbols === true ) pool = pool.concat(pools.symbols);
        if ( pool.length === 0 ) return;

        var string = '';
        for (var i = 0; i < length; i++) string += pool.charAt(Math.floor(Math.random() * pool.length));
        return string;

    }

    /**
     * @function
     * @param {string} password - Password to check
     * @returns {number} Returns the calculated strength of the provided password.
     * @description Calculate the strength of a supplied password
     */
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

/**
 * @namespace
 * @class
 * @classdesc Keychain Management and Storage Engine based on LocalStorage and AEAD encryption
 *
 * ## Keychain Introduction
 *
 * This class is designed to generate and maintain cryptographic data and optionally store it in localStorage. It supports multiple encryption key configurations, recovery keys, 256-bit XChaCha20-Poly1305 AEAD encryption, and more.
 *
 * ### Basic Features
 * 1. Store and manage multiple key configurations
 * 1. Provide recovery keys and codes to restore access when a password or key is lost
 * 1. Storage is namespaced and will not overlap with other keys
 * 1. Storage keys and data are fully encrypted with an encryption key and salt not accessible by looking at stored configuration
 * 1. Encryption password changeable without rewriting encrypted storage
 * 1. Storage is optional and keychain can be used purely for temporary data/message encryption
 *
 * ### Recipes
 *
 * #### First Time Key Creation
 *
 * *Uses: keychain.{@link SeaSalt_Keychain#create create}(), SeaSalt_Tools.{@link SeaSalt_Tools#randomString randomString}()*
 *
 * ```js
 * //  first let's initiate the keychain
 * //  it will attempt to locate keychain data; otherwise it creates a new keychain
 * let keychain = new SeaSalt_Keychain();
 *
 * //  okay, now let's make a new encryption key configuration
 * //  first we need a good, strong password. here we will generate one using SeaSalt_Tools.randomString
 * let password = keychain.tools.randomString(32); // returns a password like: ]IK4,=Qa?3,@@?@AW`N&or_l#eTy+K^:
 *
 * //  next let's create a keychain and provide it a good name
 * let result = keychain.create('My Keychain', password);
 *
 * //  result should now contain an object with the key signature and recovery codes
 * //  in the event you lose the password or encryption key data, the recovery codes and keys can be used to restore access
 * ```
 *
 * #### Encrypting and Decrypting Data
 *
 * *Uses: keychain.{@link SeaSalt_Keychain#encrypt encrypt}(), keychain.{@link SeaSalt_Keychain#decrypt decrypt}()*
 *
 * ```js
 * //  now that you've got your key setup, let's use it.
 * let original = 'My original message or string';
 * let ciphertext = keychain.encrypt(original);
 *
 * //  ciphertext should look like: 4bd7b37447fb3495349f82e8d0da1fe14b27f3182102cf9cc1c5d7ec9c638c11...
 * //  later on you decide to decrypt it
 * let decrypted = keychain.{@link SeaSalt_Keychain#decrypt decrypt}(ciphertext);
 *
 * //  decrypted should contain: My original message or string
 * ```
 *
 * #### Encrypting and Decrypting LocalStorage
 *
 * * *Uses: keychain.{@link SeaSalt_Keychain#read read}(), keychain.{@link SeaSalt_Keychain#write write}()*
 *
 * ```js
 * //  basically the same as above but using different methods to facilitate the storage part
 * let storagekey = keychain.{@link SeaSalt_Keychain#write write}('my storage key', original);
 *
 * //  the storage key name you specify is encrypted according to keychain.{@link SeaSalt_Keychain#key key}(key)
 * //  in this case, the key might look like seasalt:keychain:APxqB8gbHUWn:0:17771942b10497dc9d3a7f81b46e7cee2149f08dfed943a61562c7b69886d1b5...
 * //  and the storage contents might look like: ae47fab647c46d3693c287cee088f9997d57996e73155a6d58191775611f22c4...
 *
 * //  later you decide to read the file
 * let decrypted = keychain.read('my storage key');
 *
 * //  storage key names are unique to each key configuration. if you were to load a different key config and read the same storage key the result would be empty or an entirely different result.
 * ```
 *
 * #### Security for the Paranoid
 *
 * * *Uses: keychain.{@link SeaSalt_Keychain#update update}(), keychain.{@link SeaSalt_Keychain#rekey rekey}()*
 *
 * ```js
 * //  okay, so let's say you want to make it really difficult for an attacker break in
 *
 * //  first, without changing your password you could instead repackage the secret box
 * //  the secret box contains the encryption key and salt
 * //  you can regenerate its secret box easily without changing the password
 * keychain.update();
 *
 * //  this time we'll change the password and generate new secret box
 * let newPassword = keychain.tools.randomString(32);
 * keychain.update(newPassword);
 *
 * //  but what if that isn't enough? you can instead rekey the encryption key
 * //  this will generate a new encryption key, secret box, and update any locally encrypted data with the new key
 * //  this will also invalidate all existing recovery tokens and history data!
 * keychain.rekey(true);
 * ```
 *
 * #### Using Recovery Codes
 *
 * *Uses: keychain.{@link SeaSalt_Keychain#find_recovery find_recovery}(), keychain.{@link SeaSalt_Keychain#restore_recovery restore_recovery}(), keychain.{@link SeaSalt_Keychain#read read}(), SeaSalt_Tools.{@link SeaSalt_Tools#randomString randomString}()*
 *
 * ```js
 * //  first, let's restore from a recovery key presently in the configuration
 * //  let's test our recovery token using a key signature a recovery code we saved from keychain.create()
 * let keychain = new SeaSalt_Keychain();
 * let recoverykeys = keychain.find_recovery('P9WgA8taa9nc', '147918090902');
 *
 * //  recoverykeys should now be an array with at least one recovery key stored inside it
 * //  we can restore it directly
 * let newPassword = keychain.tools.randomString(32);
 * keychain.restore_recovery('P9WgA8taa9nc', '147918090902', recoverykeys, newPassword);
 *
 * //  alternatively, if the keychain is missing you could instead provide the recoverykey yourself
 * keychain.restore_recovery('P9WgA8taa9nc', '147918090902', '6ccc93ea0679919986391ec327f7414587ff75641157532ddb736dcbca4498f4...', newPassword);
 *
 * //  if successful the key will be restored and automatically opened
 * //  we should be able to read its storage keys again
 * keychain.read('my storage key');
 * ```
 * @property {Object} [config] - Keychain configuration
 * @property {boolean} [config.debug=false] - Whether or not SeaSalt_Keychain is running in debugging mode
 * @property {string} [config.hash=sha512] - Hashing algorithm to use (sha256, sha512)
 * @property {number} [config.recoveryTokenCount=2] - Number of recovery tokens to generate when creating a new key
 * @property {number} [config.recoveryTokenLength=12] - Length of the recovery code
 * @property {number} [config.maxRecoveryPoints=5] - Maximum number of recovery keys to keep per signature
 * @property {number} [config.maxRecoveryAge] - Maximum length of time in milliseconds to keep a recovery key before automatically deleting it
 * @property {number} [config.signatureLength=12] - Length of generates key signatures
 * @property {number} [config.saltLength=8] - Length of the public salt for hashing
 * @property {number} [config.keysaltLength=8] - Length of the private key salt for hashing
 * @property {Object} [config.storage] - Storage API bindings and settings (custom methods must interface localStorage)
 * @property {boolean} [config.storage.enabled=true] - Whether or not to enable localStorage.
 *
 * Setting this to `false` will disable keychain.{@link SeaSalt_Keychain#read read}, keychain.{@link SeaSalt_Keychain#write write}, keychain.{@link SeaSalt_Keychain#purge purge}, and keychain.{@link SeaSalt_Keychain#rekey rekey}.
 * @property {string} [config.storage.prefix=seasalt:keychain:] - Prefix for all storage keys
 * @property {function} [config.storage.read=localStorage.getItem] - Function for reading from storage keys
 * @property {function} [config.storage.write=localStorage.setItem] - Function for writing to storage keys
 * @property {function} [config.storage.list=Object.keys(localStorage)] - Lists all found storage keys
 * @property {function} [config.log] - Function for handling logging calls
 * @property {boolean} ready - Keychain state
 * @property {Object} keys - Keychain configuration data keychain.{@link SeaSalt_Keychain#keyconf keyconf}
 * @property {Object} history - Stored secret boxes whose configuration has otherwise been deleted
 * @example <caption>Basic Usage</caption>
 * let keychain = new SeaSalt_Keychain();
 * @example <caption>Provide a Configuration</caption>
 * let keychain = new SeaSalt_Keychain({
 *     hash: sha256,
 *     recoveryTokenCount: 3,
 *     storage: {
 *         prefix: 'mycustom:prefix:'
 *     }
 * });
 * @example <caption>Open key configuration on construction</caption>
 * let keychain = new SeaSalt_Keychain('APxqB8gbHUWn', 'mypassword');
 */
class SeaSalt_Keychain {

    /**
     * @function
     * @param {Object | string} [sig] - Key signature or initial config
     * @param {string} [password] - Key password or keychain data
     * @param {Object} [config] - User configuration
     * @param {string} [data] - Keychain data
     */
    constructor(sig, password, config, data) {

        if ( typeof sig === 'object' ) {

            config = sig;
            data = password;
            sig = undefined;
            password = undefined;

        }

        this.test = [];
        this.config = {
            debug: true,
            hash: 'sha512',
            recoveryTokenCount: 2,
            recoveryTokenLength: 12,
            maxRecoveryPoints: 5,
            maxRecoveryAge: undefined,
            signatureLength: 12,
            saltLength: 8,
            keysaltLength: 8,
            storage: {
                enabled: true,
                prefix: 'seasalt:keychain:',
                read: function(key) {
                    return localStorage.getItem(key);
                },
                write: function(key, value) {
                    return localStorage.setItem(key, value);
                },
                delete: function(key) {
                    return localStorage.removeItem(key);
                },
                list: function() {
                    return Object.keys(localStorage);
                }
            },
            log: undefined
        };

        //  support constructor passing signature and password before config and data
        if ( typeof sig === 'string' && typeof password === 'string' ) {

            this.config.sig = sig;
            this.config.password = password;
            sig = undefined;
            password = undefined;

        }

        //  import user-provided config
        if ( typeof config === 'object' ) Object.keys(config).filter(function(key) {
            this.config[key] = config[key];
        });

        //  prepare the base properties and methods
        if ( typeof this.config.storage.prefix !== 'string' ) this.error('No storage prefix has been specified');
        if ( typeof this.config.log !== 'function' ) this.config.log = function() {
            if ( this.config.debug === true ) {
                if ( typeof arguments[0] === 'string' ) console.log.apply(null, arguments);
                if ( typeof arguments[0] === 'object' ) console.error(null, arguments);
            }
        };

        this.aead = new SeaSalt_AEAD_XChaCha();
        this.tools = new SeaSalt_Tools();
        this.ready = false;
        this.keys = {};
        this.history = {};
        this.enabled = true;
        this.active = undefined;
        this.keysalt = '0xk*S#x9';
        let self = this;

        //  if no keychain is provided let's try to load it ourselves
        if ( typeof data !== 'string' ) try {
            data = this.config.storage.read(this.config.storage.prefix + 'keyring');
        } catch(e) {}

        //  try loading the keychain
        if ( typeof data === 'string' ) {

            let keychain;
            try {
                keychain = JSON.parse(data);
            } catch (e) {}
            if ( typeof keychain === 'object' ) {

                this.log('SeaSalt/Keychain loading stored keychain from localStorage');
                Object.keys(keychain).filter(function (key) {
                    self[key] = keychain[key];
                });

            }

        }

        this.ready = true;
        this.log('SeaSalt/Keychain loaded successfully');

        if ( this.config.sig && this.config.password ) {

            try {
                this.open(this.config.sig, this.config.password);
            } catch(e) {
                delete this.config.sig;
                delete this.config.password;
                this.error('SeaSalt/Keychain failed to open key with error: ' + e);
            }

            delete this.config.sig;
            delete this.config.password;

        }

    }

    /**
     * @function
     * @param {...*} arg - Arguments to forward to logging handler
     * @description Forwards logging requests to the configured log handler
     */
    log(arg) {

        this.config.log.apply(this, arguments);

    }

    /**
     * @function
     * @param {string} string - String to hash
     * @param {string} [salt=Empty] - Salt to hash with
     * @returns {string} Returns a hash of the input
     * @description Hash an input using the configured hashing algorithm with optional salt
     */
    hash(string, salt) {

        if ( typeof salt !== 'string' ) salt = '';
        return (new SeaSalt_Hashing(salt + string + salt, this.config.hash)).toString();

    }

    /**
     * @function
     * @param {string | exception} message - Error message to throw
     * @description Forward an error and throw it
     */
    error(message) {

        throw message;

    }

    /**
     * @function
     * @param {Object} config - Keychain key configuration values
     * @param {string} config.box - Secret box for the key
     * @param {string} config.name - Key configuration name
     * @param {string} config.salt - Key configuration public salt
     * @param {number} [config.format=0] - Key configuration format
     * @param {Array} [config.history=[]] - Previous secret box strings
     * @param {Object} [config.recovery={}] - Recovery code objects
     * @returns {object}
     * @description Returns a new key configuration (generally for creation and restoration of key configurations)
     * @example
     * let keychain = new SeaSalt_Keychain();
     *
     * //  the keys name, box, and salt are required
     * keychain.keyconf({
     *    name: 'My config name',
     *    box: 'Secret box string',
     *    salt: 'Public salt'
     * });
     */
    keyconf(config) {

        let object = {
            format: 0,
            box: '',
            name: '',
            salt: '',
            history: [],
            recovery: {}
        };

        if ( typeof config !== 'object' ) config = {};
        Object.keys(config).filter(function(key) {
            if ( typeof object[key] === 'undefined' ) return;
            object[key] = config[key];
        });

        if ( object.box === '' || object.name === '' || object.salt === '' ) this.error('Supplied key configuration is incomplete');
        return object;

    }

    /**
     * @function
     * @returns {string} JSON object of keychain data
     * @description Convert the keychain into a JSON object for storage
     */
    toJSON() {

        return JSON.stringify({
            keys: this.keys,
            history: this.history,
            enabled: this.enabled
        });

    }

    /**
     * @function
     * @returns {boolean} True or false depending on save status
     * @description Store the keychain to localStorage
     */
    save() {

        if ( this.config.storage.enabled !== true ) {
            this.log('SeaSalt/Keychain is bypassing a save request because localStorage is turned off');
            return true;
        }

        try {

            this.config.storage.write(this.config.storage.prefix + 'keyring', this.toJSON());
            this.log('SeaSalt/Keychain successfully wrote keychain to localStorage');

        } catch(e) {
            this.log('SeaSalt/Keychain failed to write keychain to localStorage');
            this.log(e);
            return false;
        }

        return true;

    }

    /**
     * @function
     * @param {string} name - Name for this key configuration
     * @param {string} userPassword - Password for the key configuration
     * @returns {Object | boolean} Returns an object containing the key signature and recovery codes/keys or false on failure
     * @description Create a new key configuration.
     *
     * #### Recovery Codes
     * The recovery codes are used to access the recovery keys.
     *
     * The recovery keys contain a copy of the original encryption key. A few are generated at creation and are stored in the keychain. You can create more later on.
     *
     * If you have they keychain, then you only need the recovery codes to use the keys. If you lose the keychain entirely, then you can provide both the code and key at restoration time.
     * @example
     * let keychain = new SeaSalt_Keychain();
     * keychain.create('My config name', 'mymuchbetterpassword');
     *
     * //  returns an object like
     * {
     *      "sig": "aVXT41Qvhkzn",
     *      "codes": {
     *           "333400752028": "8db9a168853bfa778b510f93b99f8783ba48f0b7a8a7c31eaf317437dc9f22b4...",
     *           "686119075418": "6ccc93ea0679919986391ec327f7414587ff75641157532ddb736dcbca4498f4..."
     *      }
     * }
     */
    create(name, userPassword) {

        let sig = (new SeaSalt_Tools()).randomString(this.config.signatureLength, true, true, true, false);
        let salt = (new SeaSalt_Tools()).randomString(this.config.saltLength);
        let keysalt = (new SeaSalt_Tools()).randomString(this.config.keysaltLength);
        let passphrase = this.hash(this.hash(userPassword), salt);
        let secretbox = new SeaSalt_AEAD_SecretBox(passphrase, {
            keysalt: keysalt,
            secret: this.aead.key()
        });

        this.keys[sig] = this.keyconf({
            box: secretbox.box,
            name: name,
            salt: salt
        });

        let codes = {};
        for ( let i = 0; i < this.config.recoveryTokenCount; i++ ) {
            let data = this.create_recovery(sig, userPassword);
            this.keys[sig].recovery[this.hash(data.code)] = data.token;
            codes[data.code] = data.token;
        }

        if ( !this.active ) {
            this.active = sig;
            this.passphrase = passphrase;
            this.keysalt = keysalt;
        }

        if ( this.save() === true ) return {sig: sig, codes: codes};
        return false;

    }

    /**
     * @function
     * @param {string} sig - Key configuration signature
     * @param {string | Object} data - JSON object of the key configuration data
     * @returns {boolean} Returns true or false
     * @description Imports a key configuration to the keychain
     * @example
     * let keychain = new SeaSalt_Keychain();
     * keychain.import_key('aVXT41Qvhkzn', 'cd052b20c5dabb034975baae5c17e2b65521c5a9971fac10022874b557653e2f...');
     */
    import_key(sig, data) {

        if ( this.ready !== true ) this.error('Keychain state not ready');

        if ( typeof data === 'string' ) try {
            data = JSON.parse(data);
        } catch(e) {}
        if (
            typeof data !== 'object' ||
            data.format !== 0 ||
            typeof data.name !== 'string' ||
            typeof data.box !== 'string'
        ) return false;

    }

    /**
     * @function
     * @param {string | boolean} [sig] - Specific key signature, true for all, or none for currently opened key
     * @returns {string} Returns a JSON object of the requested key configuration data
     * @description Export the current sig, specified sig, or all sigs keychain data
     * @example
     * let keychain = new SeaSalt_Keychain();
     *
     * //  export all key configurations
     * keychain.export_key();
     *
     * //  export a specific key configuration
     * keychain.export_key('aVXT41Qvhkzn');
     *
     */
    export_key(sig) {

        if ( this.ready !== true || (sig !== true && this.listkeys().indexOf(sig || this.active) === -1) ) this.error('Keychain state not ready');
        return JSON.stringify(( sig === true ) ? this.keys : this.keys[sig || this.active], null, 5);

    }

    /**
     * @function
     * @param {string} sig - Key configuration signature
     * @param {string} [userPassword] - Password for the key configuration
     * @returns {boolean} Returns true or false
     * @description Attempt to read and parse a keychain entry (or open the only existing key if sig omitted)
     * @example <caption>Basic Usage</caption>
     * let keychain = new SeaSalt_Keychain();
     * keychain.open('aVXT41Qvhkzn', 'mygreatpassword');
     * @example <caption>Usage with a Single Key Config</caption>
     * let keychain = new SeaSalt_Keychain();
     * keychain.open('mygreatpassword');
     */
    open(sig, userPassword) {

        if ( !userPassword ) {

            //  if no password was provided then we'll assume the provided signature is the password
            userPassword = sig;

            //  this is only allowed if a single key is installed on the keychain
            let keys = this.listkeys();
            sig = ( keys.length === 1 ) ? keys[0] : undefined;

        }

        if ( this.ready !== true || typeof this.keys[sig] !== 'object' ) this.error('Keychain state not ready or invalid signature provided');

        let passphrase = this.hash(this.hash(userPassword), this.keys[sig].salt);

        //  test the passphrase against the key
        let encrypted;
        let aead = new SeaSalt_AEAD_XChaCha();
        try {
            encrypted = aead.encrypt('testing', passphrase, this.keys[sig].box);
            if (aead.decrypt(encrypted, passphrase, this.keys[sig].box) !== 'testing') {
                return false;
            }
        } catch(e) { throw e; }

        //  key is valid
        this.active = sig;
        this.passphrase = passphrase;
        this.keysalt = this.get_keysalt();
        this.log('SeaSalt/Keychain opened key with signature: ' + sig);
        return true;

    }

    /**
     * @function
     * @returns {boolean}
     * @description Close an opened key and erase all loaded settings
     */
    close() {

        this.active = undefined;
        this.passphrase = undefined;
        this.keysalt = undefined;
        return true;

    }

    /**
     * @function
     * @param {string} [newPassword] - New password for the key configuration
     * @returns {boolean} Returns true or false
     * @description Repackages currently opened secret box optionally with a new password
     * @example <caption>Repackage a secret box without changing the password</caption>
     * let keychain = new SeaSalt_Keychain();
     * keychain.open('aVXT41Qvhkzn', 'mygreatpassword');
     * keychain.update();
     * @example <caption>Repackage a secret box and change the password</caption>
     * let keychain = new SeaSalt_Keychain();
     * keychain.open('aVXT41Qvhkzn', 'mygreatpassword');
     * keychain.update('mysuperbetterpassword1');
     */
    update(newPassword) {

        if ( this.ready !== true || this.listkeys().indexOf(this.active) === -1 ) this.error('Keychain state not ready');

        //  if this signature already exists, copy it into the recovery keys
        if ( typeof newPassword === 'string' && typeof this.keys[this.active] === 'object' ) this.store_history();

        //  generate and store the new secretbox
        let passphrase = ( typeof newPassword === 'string' ) ? this.hash(this.hash(newPassword), this.keys[this.active].salt) : undefined;
        this.keys[this.active].box = (new SeaSalt_AEAD_SecretBox()).repackage(this.keys[this.active].box, this.passphrase, passphrase || this.passphrase);
        if ( passphrase ) this.passphrase = passphrase;
        return this.save();

    }

    /**
     * @function
     * @param {string} [sig] - Key configuration signature
     * @returns {boolean} Returns true or false
     * @description Stores the specified key signature or loaded key signature's secret box in the recovery chain.
     */
    store_history(sig) {

        if ( this.ready !== true || this.listkeys().indexOf(sig || this.active) === -1 ) this.error('Keychain state not ready');
        this.keys[sig || this.active].history.push(this.keys[sig || this.active].box);
        return this.save();

    }

    /**
     * @function
     * @param {string} sig - Key configuration signature
     * @param {string} userPassword - Hashed passphrase of the userPassword
     * @param {string} [box] - Secret box to use for creating the recovery object
     * @returns {Object} Returns an object containing a recovery code and recovery key
     * @description Generates a random code and corresponding secret box
     * @example <caption>Basic Usage</caption>
     * let keychain = new SeaSalt_Keychain();
     * keychain.create_recovery('aVXT41Qvhkzn', 'mygreatestpasswordyet')
     *
     * //  returns an object like
     * {
     *      "code": "482559516047",
     *      "token": "cd052b20c5dabb034975baae5c17e2b65521c5a9971fac10022874b557653e2f..."
     * }
     * @example <caption>Providing an Alternate Secret Box</caption>
     * //  let's say we want to use the first key stored in the key history
     * let keychain = new SeaSalt_Keychain();
     * keychain.create_recovery('aVXT41Qvhkzn', 'mygreatestpasswordyet', keychain.keys.aVXT41Qvhkzn.history[0])
     */
    create_recovery(sig, userPassword, box) {

        if ( !box && (typeof this.keys[sig || this.active] !== 'object' || typeof userPassword !== 'string') ) this.error('Invalid arguments');
        let passphrase = this.hash(this.hash(userPassword), this.keys[sig || this.active].salt);
        let code = this.tools.randomString(this.config.recoveryTokenLength, false, false, true, false);
        let token = (new SeaSalt_AEAD_SecretBox()).repackage(box || this.keys[sig || this.active].box, passphrase, this.hash(this.hash(code), this.keys[sig || this.active].salt));
        return {
            code: code,
            token: token
        };

    }

    /**
     * @function
     * @param {string} sig - Key configuration signature
     * @param {string} code - Recovery code to attempt validating
     * @param {string | Array} [boxes] - Box or boxes to try validating against
     * @returns {Array} Returns an array of all matching secret boxes
     * @description Check supplied code against all known or provided secret boxes
     * @example <caption>Basic Usage</caption>
     * let keychain = new SeaSalt_Keychain();
     * keychain.find_recovery('aVXT41Qvhkzn', '482559516047');
     * @example <caption>Providing an Alternate Secret Box</caption>
     * //  in this case, let's say you are able to provide a copy of the recovery code and token
     * let keychain = new SeaSalt_Keychain();
     * keychain.find_recovery('aVXT41Qvhkzn', '482559516047', 'cd052b20c5dabb034975baae5c17e2b65521c5a9971fac10022874b557653e2f...');
     */
    find_recovery(sig, code, boxes) {

        if ( typeof this.keys[sig] !== 'object' ) this.error('Invalid signature');
        if ( typeof boxes === 'undefined' ) boxes = Object.values(this.keys[sig].recovery);
        if ( typeof boxes === 'string' ) boxes = [boxes];
        if ( !Array.isArray(boxes) ) return [];
        let self = this;

        boxes = boxes.filter(function(box) {

            let encrypted;
            try {
                encrypted = self.aead.encrypt('testing', self.hash(self.hash(code), self.keys[sig].salt), box);
            } catch(e) {}
            if ( !encrypted ) return false;
            let decrypted;
            try {
                decrypted = self.aead.decrypt(encrypted, self.hash(self.hash(code), self.keys[sig].salt), box);
            } catch(e) {}
            return ( decrypted === 'testing' );

        });

        return boxes;

    }

    /**
     * @function
     * @param {string} sig - Key configuration signature
     * @param {string} code - Recovery code to utilize
     * @param {string | Array} boxes - Box or boxes to try recovering from
     * @param {string} newPassword - New password for the key configuration
     * @returns {boolean} Returns true or false
     * @description Installs the provided secret box (or the first valid in an array) to the specified key and resets a new password
     * @example
     * let keychain = new SeaSalt_Keychain();
     * let recoveryboxes = keychain.{@link SeaSalt_Keychain#find_recovery find_recovery}('aVXT41Qvhkzn', '482559516047');
     * keychain.restore_recovery('aVXT41Qvhkzn', '482559516047', recoveryboxes, 'mysuperdupernewpassword');
     */
    restore_recovery(sig, code, boxes, newPassword) {

        if ( typeof this.keys[sig] !== 'object' ) this.error('Invalid signature');
        if ( typeof boxes === 'string' ) boxes = [boxes];
        if ( !Array.isArray(boxes) ) this.error('Supplied box is not valid');

        let self = this;
        let passphrase = this.hash(this.hash(newPassword), this.keys[sig].salt);
        let codephrase = this.hash(this.hash(code), this.keys[sig].salt);
        let secretbox;
        boxes.filter(function(box) {
            if ( typeof secretbox === 'string' ) return;
            try {
                secretbox = (new SeaSalt_AEAD_SecretBox()).repackage(box, codephrase, passphrase);
            } catch(e) {}
        });

        if ( typeof secretbox !== 'string' ) return false;

        this.store_history(sig);
        this.active = sig;
        this.passphrase = passphrase;
        this.ready = true;
        this.keys[sig].box = secretbox;
        this.keysalt = this.get_keysalt();
        return true;

    }

    /**
     * @function
     * @param {string} key - Storage key name to modify
     * @returns {string} Returns a string containing the new storage key name
     * @description Converts a key to the encrypted-format key with format: <span style="color: red">prefix</span>:<span style="color: green">key signature</span>:<span style="color: blue">key format</span>:<span style="color: orange">encrypted storage key</span>
     *
     * Example: <span style="color: red">seasalt:keychain</span>:<span style="color: green">FaWDuAFuZlyRg6IG</span>:<span style="color: blue">0</span>:<span style="color: orange">a8c0b162cacd0cb76803da4c5eb0269e...</span>
     *
     * The encrypted storage key is a hash of the provided key and the private keysalt.
     * @example
     * let keychain = new SeaSalt_Keychain();
     * keychain.key('my storage key');
     *
     * //  returns a string like: seasalt:keychain:aVXT41Qvhkzn:0:a8c0b162cacd0cb76803da4c5eb0269e...
     */
    key(key) {

        if ( this.ready !== true || this.listkeys().indexOf(this.active) === -1 ) this.error('Keychain state not ready');
        return this.config.storage.prefix + this.active + ':' + this.keys[this.active].format + ':' + this.hash(key, this.keysalt);

    }

    /**
     * @function
     * @returns {string} Returns the found keysalt value
     * @description Get the private keysalt for the currently open key configuration
     */
    get_keysalt() {

        if ( this.ready !== true || typeof this.keys[this.active] !== 'object' ) this.error('Keychain state not ready or invalid signature provided');
        let jsdoc = (new SeaSalt_AEAD_XChaCha()).decrypt(this.keys[this.active].box, this.passphrase);
        try {
            jsdoc = JSON.parse(jsdoc);
        } catch(e) {}
        if ( typeof jsdoc === 'object' && jsdoc.keysalt ) return jsdoc.keysalt;
        this.error('Failed to locate keysalt');

    }

    /**
     * @function
     * @param {string} string - String to encrypt
     * @returns {string} Returns the encrypted ciphertext
     * @description Encrypt a string using the loaded key configuration encryption key.
     *
     * Encryption utilizes AEAD with nonces. The same string and key will never result in the same ciphertext twice.
     * @example
     * let keychain = new SeaSalt_Keychain();
     * keychain.open('aVXT41Qvhkzn', 'mygreatpassword33');
     * keychain.encrypt('My secret string');
     *
     * //  returns a string like: 1a0a8965c5995dbfbb9e32706805e0d7c3bcdd080107d8929cb36f358af25825eb82cab9e2ce38363ed6f3e999b785e1823185a8ce4272ac
     */
    encrypt(string) {

        if ( this.ready !== true || this.listkeys().indexOf(this.active) === -1 ) this.error('Keychain state not ready');
        return (new SeaSalt_AEAD_XChaCha()).encrypt(string, this.passphrase, this.keys[this.active].box);

    }

    /**
     * @function
     * @param {string} ciphertext - Ciphertext to decrypt
     * @returns {string} Returns the decrypted string
     * @description Decrypt a provided ciphertext using the loaded key
     * @example
     * let keychain = new SeaSalt_Keychain();
     * keychain.open('aVXT41Qvhkzn', 'mygreatpassword33');
     * keychain.decrypt('1a0a8965c5995dbfbb9e32706805e0d7c3bcdd080107d8929cb36f358af25825eb82cab9e2ce38363ed6f3e999b785e1823185a8ce4272ac');
     *
     * //  using the example from keychain.{@link SeaSalt_Keychain#encrypt encrypt} the result would be: My secret string
     */
    decrypt(ciphertext) {

        if ( this.ready !== true || this.listkeys().indexOf(this.active) === -1 ) this.error('Keychain state not ready');
        return (new SeaSalt_AEAD_XChaCha()).decrypt(ciphertext, this.passphrase, this.keys[this.active].box);

    }

    /**
     * @function
     * @param {string} key - Storage key to read
     * @returns {string | undefined} Returns the decryption result data
     * @description Read and decrypt a string from storage
     * @example <caption>Basic Usage</caption>
     * let keychain = new SeaSalt_Keychain('aVXT41Qvhkzn', 'mygreatpassword33');
     * keychain.read('mystoragekey1');
     *
     * //  using the example from keychain.{@link SeaSalt_Keychain#write write} the result would be: Hello world
     */
    read(key) {

        if ( this.ready !== true || this.listkeys().indexOf(this.active) === -1 ) this.error('Keychain state not ready');
        if ( this.config.storage.enabled !== true ) {
            this.log('SeaSalt/Keychain is bypassing a read request because localStorage is turned off');
            return;
        }

        let ciphertext;
        try {
            ciphertext = this.config.storage.read(this.key(key));
        } catch(e) {}
        if ( !ciphertext ) return;
        return this.decrypt(ciphertext);

    }

    /**
     * @function
     * @param {string} key - Storage key to write
     * @param {string} value - String to be encrypted and stored
     * @returns {string | boolean} Returns the storage key name or false
     * @description Encrypts and writes data to storage.
     *
     * Storage key names are unique to each key configuration. Thus storage key names do not need to be unique between key configurations.
     *
     * See keychain.{@link SeaSalt_Keychain#key key} for information regarding the returned key format.
     * @example
     * let keychain = new SeaSalt_Keychain('aVXT41Qvhkzn', 'mygreatpassword33');
     * keychain.write('mystoragekey1', 'Hello world');
     *
     * //  returns a string like: seasalt:keychain:aVXT41Qvhkzn:0:44f3ef019ab2cd691a7d102cf8471d0d43f95d7c5582568885a4975c91a0ecb9...
     */
    write(key, value) {

        if ( this.ready !== true || this.listkeys().indexOf(this.active) === -1 ) this.error('Keychain state not ready');
        if ( this.config.storage.enabled !== true ) {
            this.log('SeaSalt/Keychain is bypassing a write request because localStorage is turned off');
            return false;
        }
        if ( typeof key !== 'string' || typeof value !== 'string' ) this.error('Arguments not valid');

        //  encrypt the supplied value
        let ciphertext = this.encrypt(value);
        if ( typeof ciphertext !== 'string' ) return false;

        //  generate our encrypted key
        key = this.key(key);

        //  attempt to store the data object to localStorage
        try {
            this.config.storage.write(key, ciphertext);
        } catch(e) {
            return false;
        }
        return key;

    }

    /**
     * @function
     * @param {string | boolean} [sig] - Key configuration signature to destroy (treated as history if boolean)
     * @param {boolean} [history] - Whether or not to delete history data for this key configuration
     * @param {boolean} [purge] - Whether or not to purge all key data storage
     * @description Destroys a key signature by deleting it from the keychain
     * @example <caption>Basic Usage</caption>
     * //  destroy the key configuration but do not delete the history or storage data
     * let keychain = new SeaSalt_Keychain();
     * keychain.destroy('aVXT41Qvhkzn');
     * @example <caption>Advanced Usage</caption>
     * //  destroy the key configuration, history and storage data
     * keychain.destroy('aVXT41Qvhkzn', true, true);
     *
     * //  destroy all key configurations and data
     * keychain.destroy(true, true);
     */
    destroy(sig, history, purge) {

        if ( typeof sig === 'boolean' ) {

            purge = history;
            history = sig;
            sig = undefined;

        }

        if ( this.ready !== true || this.listkeys().indexOf(sig || this.active) === -1 ) throw 'Signature does not exist or keychain is not ready';
        if ( history !== true ) this.history[sig || this.active] = this.keys[sig || this.active];
        delete this.keys[sig || this.active];
        if ( purge === true ) this.purge(sig || this.active, false, true);
        if ( sig === undefined || sig === this.active ) this.close();
        return this.save();

    }

    /**
     * @function
     * @returns {Array}
     * @description Return a list of key configuration signatures
     */
    listkeys() {

        return Object.keys(this.keys);

    }

    /**
     * @function
     * @param {string} [sig] - Key configuration signature
     * @param {boolean} [all=false] - Whether or not to purge all data and not just storage data
     * @param {boolean} confirm - Whether or not you confirm this command
     * @param {boolean} [reverse=false] - Whether or not to erase all data that doesn't match key configuration signature
     * @param {boolean} [history=false] - Whether or not to erase all associated history data
     * @returns {object | undefined} Returns an object listing all deleted key signatures and storage keys
     * @description Purge data from the keychain and storage
     * @example <caption>Basic Usage</caption>
     * //  delete all storage data for specified key configuration
     * let keychain = new SeaSalt_Keychain();
     * keychain.purge('aVXT41Qvhkzn', false, true);
     * @example <caption>Advanced Usage</caption>
     * //  delete storage and key configuration data
     * keychain.purge('aVXT41Qvhkzn', true, true);
     *
     * //  delete storage, key configuration, and history data
     * keychain.purge('aVXT41Qvhkzn', true, true, false, true);
     *
     * //  delete all storage data for keys other than the one specified
     * keychain.purge('aVXT41Qvhkzn', false, true, true);
     *
     * //  delete all data
     * keychain.purge(undefined, true, true);
     */
    purge(sig, all, confirm, reverse, history) {

        if ( typeof this.keys[sig] !== 'object' && all !== true ) this.error('Signature does not exist');
        if ( this.config.storage.enabled !== true ) {
            this.log('SeaSalt/Keychain is bypassing a purge request because localStorage is turned off');
            return;
        }
        if ( typeof all !== 'boolean' ) this.error('Invalid arguments');
        if ( confirm !== true ) this.error('You must confirm this action in the third argument');

        let self = this;
        let keys = this.config.storage.list().filter(function(key) {

            if ( reverse === true ) {
                return (
                    key.indexOf(self.config.storage.prefix) > -1 &&
                    key.indexOf('keyring') === -1 &&
                    key.indexOf(sig) === -1
                );
            } else {
                return ( key.indexOf(self.config.storage.prefix) > -1 && key.indexOf(sig) > -1 );
            }

        });

        //  delete all of the matching keys and collect a list of unique signatures
        let sigs = [];
        keys.filter(function(key) {
            self.config.storage.delete(key);
            let regex = new RegExp('^' + self.config.storage.prefix + '([a-zA-Z0-9]*):[0-9]*?:.*$');
            let matches = key.match(regex);
            if ( matches !== null && sigs.indexOf(matches[1]) === -1 ) sigs.push(matches[1]);
        });

        this.log('SeaSalt/Keychain purged storage keys: ' + JSON.stringify(keys));

        //  find all detectable signatures if we're doing a reverse purge
        if ( reverse === true ) Object.keys(this.keys).filter(function(csig) {
            if ( csig !== sig && sigs.indexOf(csig) === -1 ) sigs.push(csig);
        });

        //  destroy all detected signatures
        if ( all === true ) {

            this.log('SeaSalt/Keychain purged signatures: ' + JSON.stringify(sigs));
            sigs.filter(function(sig) {
                self.destroy(sig, history);
            });

        }

        //  reset keychain state if active signature was destroyed
        if ( all === true && sigs.indexOf(this.active) > -1 ) this.close();

        return {
            storage: keys,
            sigs: ( all === true ) ? sigs : []
        };

    }

    /**
     * @function
     * @param {boolean} confirm=false - Whether or not to confirm the action
     * @returns {object | undefined} Returns an object containing the key signature and new recovery codes
     * @description Create a new encryption key and rekeys associated objects in localStorage and recovery codes for currently opened key configuration.
     *
     * This action renders all prior recovery and history keys unusable. If you value your data then definitely create a backup prior to executing this command.
     */
    rekey(confirm) {

        if ( this.ready !== true || this.listkeys().indexOf(this.active) === -1 ) this.error('Keychain state not ready');
        if ( this.config.storage.enabled !== true ) {
            this.log('SeaSalt/Keychain is bypassing a rekey request because localStorage is turned off');
            return;
        }
        if ( confirm !== true ) this.error('Confirmation argument not provided');
        let deleted = this.config.storage.list().filter(function(key) {

            let regex = new RegExp('(' + this.active + ')');
            if ( key.match(regex) !== null ) {



            }

        });

    }

    /**
     * @function
     * @param {string | Array} [sigs] - Key signature or array of signatures to backup data for
     * @description Generates a backup of all Keychain data or just the specified sigs. Requires JSZip dependency.
     */
    backup(sigs) {

        if ( typeof JSZip !== 'object' || !(JSZip instanceof JSZip) ) this.error('JSZip is required for making backups');

    }

}

//  AES-256-GCM not supported in browser library
