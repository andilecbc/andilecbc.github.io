/*! PinEncryptor | (c) GNC&TCS GmbH */

const VERSION = "js-v1.0.1";

const ERRORS = {
    ERR_SUCCESS: {
        code: 0,
        description: "Success"
    },
    ERR_PIN_TOO_SHORT: {
        code: 101,
        description: "The pin is too short"
    },
    ERR_PIN_CONTAINS_LETTERS: {
        code: 102,
        description: "The pin can't contains letters"
    },
    ERR_PIN_TOO_MANY_DUPLICATES: {
        code: 103,
        description: "The pin has too many duplicates"
    },
    ERR_PIN_IS_SEQUENCE: {
        code: 104,
        description: "The pin is a sequence"
    },
    ERR_PIN_IS_PATTERN: {
        code: 105,
        description: "The pin is a pattern"
    },
    ERR_PIN_IS_PINPAD_PATTERN: {
        code: 106,
        description: "The pin is a pattern on the pin pad"
    },
    ERR_PIN_IS_BIRTHDATE: {
        code: 107,
        description: "The pin is likely a birthdate"
    },
    ERR_PIN_USED_OFTEN: {
        code: 108,
        description: "The pin is used too often, to be safe"
    }
}

function PinEncryptor(uid, publicKey) {
    this.uid = uid;
    this.publicKey = publicKey;

    this.version = function () {
        return VERSION
    };
    this.encrypt = function (pin) {
        let res = isWeak(pin);
        if (res != null) {
            return {
                version: VERSION,
                error: res
            }
        }
        // Encode PIN value and get a PIN block, explained in "PIN block encode.docx" file.
        let pinBlock = encodePin(pin);
        // Generate AES KEY 256 bits, IV 96 bits and encrypt pin block with AES GCM.
        // AES GCM has IV (nonce) with 12 bytes length.
        let aesKey = forge.random.getBytesSync(32);
        let aesIv = forge.random.getBytesSync(12);

        const cipher = forge.cipher.createCipher("AES-GCM", aesKey);
        cipher.start({iv: aesIv});
        cipher.update(forge.util.createBuffer(pinBlock));
        cipher.finish();
        let encPinBlockWithoutIvAndAuthTag = cipher.output.bytes();
        // Get authentication tag after encryption.
        let authTag = cipher.mode.tag.bytes();

        // Base64 encode of the encrypted PIN block value, without authentication tag and without initial vector ().
        // If in other programming languages implementations of the AES GCM in the result of the encrypted value are included iv and authentication tag
        // is needed to exclude this two values from encrypted bytes.
        // The final encrypted message will have only bytes that refer to the message.
        let encodedMessage = forge.util.encode64(encPinBlockWithoutIvAndAuthTag);

        // Create details and encrypt with rsa public key received from PMP API (get public key endpoint).
        // Details will include AES KEY, IV and authentication tag.
        // Details have the following format:
        //      first element is the key length as a character code
        //      the next "key length" elements are the AES KEY
        //      next element is the IV length as a character code
        //      the next "IV length" elements are the AES IV
        //      next element is the authentication tag length as a character code
        //      the next "tag length" elements are the AES GCM authentication tag
        let details = String.fromCharCode(aesKey.length) + aesKey + String.fromCharCode(aesIv.length) + aesIv + String.fromCharCode(authTag.length) + authTag;


        //Prepare RSA public key and encrypt details
        let publicKey = forge.util.decode64(this.publicKey);
        let rsaPublicKey = forge.pki.publicKeyFromPem(publicKey);
        let encryptedDetails = rsaPublicKey.encrypt(details, 'RSA-OAEP', {
            md: forge.md.sha256.create()
        });
        let encodedDetails = forge.util.encode64(encryptedDetails);

        return {
            version: VERSION,
            error: ERRORS.ERR_SUCCESS,
            uid: this.uid,
            encryptedPin: encodedMessage,
            sessionKey: encodedDetails
        }
    };

    // isWeak validates the pin value
    let isWeak = function (pin) {
        let funcsArr = [];
        funcsArr.push(function isTooShort(value) {
            if (value.length < 4) {
                return ERRORS.ERR_PIN_TOO_SHORT
            }
            return null
        });
        funcsArr.push(function isNumber(value) {
            if (/^\d*$/.test(value) == false) {
                return ERRORS.ERR_PIN_CONTAINS_LETTERS
            }
            return null
        });
        funcsArr.push(function hasDuplicates(value) {
            let digitsToCompare = [value[0], value[1]];
            for (let i = 0; i < value.length; i++) {
                let count = 0;
                for (var j = 0; j < value.length; j++) {
                    if (value[j] == digitsToCompare[i]) {
                        count++;
                    }
                }
                if (count > 2) {
                    return ERRORS.ERR_PIN_TOO_MANY_DUPLICATES
                }
            }
            return null
        });
        funcsArr.push(function isSequence(value) {
            let inner_isSequence = function(value) {
                var differences = [];
                for (i = 0; i < value.length - 1; i++) {
                    var difference = value[i + 1] - value[i];
                    differences.push(difference);
                }
                for (i = 0; i < differences.length - 1; i++) {
                    if (differences[i] != differences[i + 1]) {
                        return false;
                    }
                }
                return true
            }
            let digits = [];
            for (let i = 0; i < value.length; i++) {
                digits.push(parseInt(value[i]));
            }
            if (inner_isSequence(digits) == true) {
                return ERRORS.ERR_PIN_IS_SEQUENCE
            }
            for (i = 0; i < digits.length; i++) {
                if (digits[i] == 0) {
                    digits[i] = 10;
                }
            }
            if (inner_isSequence(digits) == true) {
                return ERRORS.ERR_PIN_IS_SEQUENCE
            }
            return null
        });
        funcsArr.push(function isPatternABAB(value) {
            let parts = [];
            for (let i = 0; i < value.length; i += 2) {
                parts.push(value.substring(i, i + 2));
            }
            for (let i = 0; i < parts.length; i++) {
                if (parts[0] != parts[i]) {
                    return null
                }
            }
            return ERRORS.ERR_PIN_IS_PATTERN
        });
        funcsArr.push(function isPatternAABB(value) {
            if(value[0] == value[1] && value[2] == value[3]) {
                return ERRORS.ERR_PIN_IS_PATTERN
            }
            return null
        });
        funcsArr.push(function isPinPadPattern(value) {
            if (value.includes('1') && value.includes('3') && value.includes('7') && value.includes('9')) {
                return ERRORS.ERR_PIN_IS_PINPAD_PATTERN
            }
            if (value == "2580" || value == "0852") {
                return ERRORS.ERR_PIN_IS_PINPAD_PATTERN
            }
            return null
        });
        funcsArr.push(function isLikelyBirthdate(value) {
            let upper = new Date().getFullYear() - 25;
            let lower = new Date().getFullYear() - 60;
            let pin = parseInt(value);
            if (pin >= lower && pin <= upper) {
                return ERRORS.ERR_PIN_IS_BIRTHDATE
            }
            return null
        });
        funcsArr.push(function isTopUsedPin(value) {
            if (value == "1004" || value == "2001") {
                return ERRORS.ERR_PIN_USED_OFTEN
            }
            return null
        });
        for (let i = 0; i < funcsArr.length; i++) {
            let res = funcsArr[i](pin);
            if (res != null) {
                return res
            }
        }
        return null
    }
    // Encode PIN value and return a PIN block, explained in "PIN block encode.docx" file.
    let encodePin = function(pin) {
        // Variable to store result of encoded PIN block
        let encodedPinArray = [];

        // Genrate random PIN block map without duplicates for indexes that indicate positions of PIN digits.
        let hasDuplicates = true;
        while (hasDuplicates == true) {
            encodedPinArray = genRanHex(50);
            hasDuplicates = hasRandomPositionsDuplicates(encodedPinArray, pin.length);
        }
        // Changing the first element in map with the PIN length value.
        encodedPinArray[0] = pin.length.toString();
        // Changing the elements in map with the PIN digits indicated in "random generated positions block (explained in "PIN block encode.docx" file)".
        for (let i = 0; i < pin.length; i++) {
            var position = parseInt(encodedPinArray[i+1], 16);
            encodedPinArray[1 + pin.length + position] = pin[i];
        }
        // Create a string from map and convert values to upper case.
        return encodedPinArray.join("").toUpperCase();
    }
    // Verify if PIN digit positions are not duplicated, explained in "PIN block encode.docx" file.
    let hasRandomPositionsDuplicates = function(array, pinLength) {
        let valuesSoFar = [];
        for (var i = 1; i <= pinLength; ++i) {
            let value = array[i];
            if (valuesSoFar.indexOf(value) !== -1) {
                return true;
            }
            valuesSoFar.push(value);
        }
        return false;
    }
    // Generates a map of randomly generated HEX values
    let genRanHex = size => [...Array(size)].map(() => Math.floor(Math.random() * 16).toString(16));
}