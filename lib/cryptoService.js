// Crypto operations used by the demo. Pure functions over node:crypto, no state.
//
// Every operation returns { output, details } where `output` is the string shown to the user
// and `details` is a plain object describing what was done (rendered as JSON in the UI).
// Bad input throws a CryptoInputError, which the controller renders as a 400.

const crypto = require('node:crypto')
const { promisify } = require('node:util')

const scrypt = promisify(crypto.scrypt)
const generateKeyPair = promisify(crypto.generateKeyPair)

// AES envelope layout (hex encoded): salt | iv | auth tag | ciphertext
const SALT_BYTES = 16
const IV_BYTES = 12
const TAG_BYTES = 16
const KEY_BYTES = 32
const DEFAULT_SCRYPT = { N: 16384, r: 8, p: 1 }
const OAEP_HASH = 'sha256'
const OAEP_HASH_BYTES = 32

class CryptoInputError extends Error {
    constructor(message) {
        super(message)
        this.name = 'CryptoInputError'
        this.status = 400
    }
}

function requireText(value, label) {
    if (typeof value !== 'string' || value.length === 0) {
        throw new CryptoInputError(`${label} is required.`)
    }
    return value
}

function deriveKey(secret, salt, params) {
    return scrypt(secret, salt, KEY_BYTES, { ...params, maxmem: 64 * 1024 * 1024 })
}

function kdfDetails(salt, params) {
    return { name: 'scrypt', N: params.N, r: params.r, p: params.p, salt: salt.toString('hex') }
}

function createCryptoService({ scryptParams = DEFAULT_SCRYPT, rsaModulusLength = 2048 } = {}) {

    async function aesEncrypt(plaintext, secret) {
        requireText(plaintext, 'Plaintext')
        requireText(secret, 'Secret')

        const salt = crypto.randomBytes(SALT_BYTES)
        const iv = crypto.randomBytes(IV_BYTES)
        const key = await deriveKey(secret, salt, scryptParams)

        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
        const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
        const tag = cipher.getAuthTag()

        return {
            output: Buffer.concat([salt, iv, tag, ciphertext]).toString('hex'),
            details: {
                algorithm: 'aes-256-gcm',
                kdf: kdfDetails(salt, scryptParams),
                iv: iv.toString('hex'),
                authTag: tag.toString('hex'),
                plaintextBytes: Buffer.byteLength(plaintext, 'utf8'),
                ciphertextBytes: ciphertext.length,
                envelope: 'hex(salt[16] | iv[12] | authTag[16] | ciphertext)'
            }
        }
    }

    async function aesDecrypt(cipherHex, secret) {
        requireText(cipherHex, 'Cipher text')
        requireText(secret, 'Secret')

        const clean = cipherHex.replace(/\s+/g, '')
        if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) {
            throw new CryptoInputError('Cipher text must be hex, as produced by AES Encrypt.')
        }
        const envelope = Buffer.from(clean, 'hex')
        const headerBytes = SALT_BYTES + IV_BYTES + TAG_BYTES
        if (envelope.length <= headerBytes) {
            throw new CryptoInputError(`Cipher text is too short: expected more than ${headerBytes} bytes (salt, IV and auth tag), got ${envelope.length}.`)
        }

        const salt = envelope.subarray(0, SALT_BYTES)
        const iv = envelope.subarray(SALT_BYTES, SALT_BYTES + IV_BYTES)
        const tag = envelope.subarray(SALT_BYTES + IV_BYTES, headerBytes)
        const ciphertext = envelope.subarray(headerBytes)
        const key = await deriveKey(secret, salt, scryptParams)

        let plaintext
        try {
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
            decipher.setAuthTag(tag)
            plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8')
        } catch {
            throw new CryptoInputError('Decryption failed: wrong secret, or the cipher text has been modified (GCM auth tag did not match).')
        }

        return {
            output: plaintext,
            details: {
                algorithm: 'aes-256-gcm',
                kdf: kdfDetails(salt, scryptParams),
                iv: iv.toString('hex'),
                authTag: tag.toString('hex'),
                authenticated: true,
                plaintextBytes: Buffer.byteLength(plaintext, 'utf8')
            }
        }
    }

    function hash(data, secret = '') {
        requireText(data, 'Plaintext')
        const keyed = typeof secret === 'string' && secret.length > 0
        const h = keyed ? crypto.createHmac('sha512', secret) : crypto.createHash('sha512')
        h.update(data, 'utf8')

        return {
            output: h.digest('hex'),
            details: {
                algorithm: keyed ? 'HMAC-SHA-512' : 'SHA-512',
                keyed,
                inputBytes: Buffer.byteLength(data, 'utf8'),
                outputBits: 512
            }
        }
    }

    async function rsaGenerateKeys() {
        const { publicKey, privateKey } = await generateKeyPair('rsa', {
            modulusLength: rsaModulusLength,
            publicExponent: 0x10001,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        })

        return {
            output: publicKey,
            publicKey,
            privateKey,
            details: {
                algorithm: 'RSA',
                modulusLength: rsaModulusLength,
                publicExponent: 65537,
                publicKeyFormat: 'PEM / SPKI',
                privateKeyFormat: 'PEM / PKCS#8 (unencrypted)',
                maxOaepPlaintextBytes: rsaModulusLength / 8 - 2 * OAEP_HASH_BYTES - 2
            }
        }
    }

    function parseKey(pem, kind) {
        try {
            return kind === 'public' ? crypto.createPublicKey(pem) : crypto.createPrivateKey(pem)
        } catch {
            throw new CryptoInputError(`Couldn't read the ${kind} key. Paste a PEM key, including the -----BEGIN/END----- lines.`)
        }
    }

    function rsaEncrypt(plaintext, publicKeyPem) {
        requireText(plaintext, 'Plaintext')
        requireText(publicKeyPem, 'Public key')

        const key = parseKey(publicKeyPem, 'public')
        if (key.asymmetricKeyType !== 'rsa') {
            throw new CryptoInputError(`Expected an RSA key, got ${key.asymmetricKeyType}.`)
        }
        const modulusLength = key.asymmetricKeyDetails.modulusLength
        const maxBytes = modulusLength / 8 - 2 * OAEP_HASH_BYTES - 2
        const data = Buffer.from(plaintext, 'utf8')
        if (data.length > maxBytes) {
            throw new CryptoInputError(`Plaintext is ${data.length} bytes; RSA-${modulusLength} with OAEP-SHA-256 can encrypt at most ${maxBytes} bytes. Real systems encrypt an AES key with RSA, not the data itself.`)
        }

        const ciphertext = crypto.publicEncrypt(
            { key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: OAEP_HASH }, data)

        return {
            output: ciphertext.toString('base64'),
            details: {
                algorithm: 'RSA-OAEP',
                oaepHash: 'SHA-256',
                modulusLength,
                plaintextBytes: data.length,
                maxPlaintextBytes: maxBytes,
                ciphertextBytes: ciphertext.length,
                encoding: 'base64'
            }
        }
    }

    function rsaDecrypt(cipherBase64, privateKeyPem) {
        requireText(cipherBase64, 'Cipher text')
        requireText(privateKeyPem, 'Private key')

        const clean = cipherBase64.replace(/\s+/g, '')
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) {
            throw new CryptoInputError('Cipher text must be base64, as produced by RSA Encrypt.')
        }
        const key = parseKey(privateKeyPem, 'private')
        if (key.asymmetricKeyType !== 'rsa') {
            throw new CryptoInputError(`Expected an RSA key, got ${key.asymmetricKeyType}.`)
        }

        let plaintext
        try {
            plaintext = crypto.privateDecrypt(
                { key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: OAEP_HASH },
                Buffer.from(clean, 'base64'))
        } catch {
            throw new CryptoInputError("Decryption failed: the private key doesn't match the public key used to encrypt, or the cipher text is corrupted.")
        }

        return {
            output: plaintext.toString('utf8'),
            details: {
                algorithm: 'RSA-OAEP',
                oaepHash: 'SHA-256',
                modulusLength: key.asymmetricKeyDetails.modulusLength,
                plaintextBytes: plaintext.length
            }
        }
    }

    async function sigGenerateKeys() {
        const { publicKey, privateKey } = await generateKeyPair('ed25519', {
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        })

        return {
            output: publicKey,
            publicKey,
            privateKey,
            details: {
                algorithm: 'Ed25519',
                curve: 'edwards25519',
                publicKeyBytes: 32,
                signatureBytes: 64,
                publicKeyFormat: 'PEM / SPKI',
                privateKeyFormat: 'PEM / PKCS#8 (unencrypted)'
            }
        }
    }

    // Ed25519/Ed448 hash internally; RSA uses PSS with SHA-256
    function signatureScheme(key) {
        switch (key.asymmetricKeyType) {
            case 'ed25519': return { name: 'Ed25519', digest: null, options: {} }
            case 'ed448': return { name: 'Ed448', digest: null, options: {} }
            case 'rsa': return {
                name: 'RSA-PSS',
                digest: 'sha256',
                options: { padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST },
                extra: { hash: 'SHA-256', saltLength: 32, modulusLength: key.asymmetricKeyDetails.modulusLength }
            }
            default:
                throw new CryptoInputError(`Can't sign with a ${key.asymmetricKeyType} key. Use an Ed25519 key from Signing Keys, or an RSA key.`)
        }
    }

    function sign(message, privateKeyPem) {
        requireText(message, 'Message')
        requireText(privateKeyPem, 'Private key')

        const key = parseKey(privateKeyPem, 'private')
        const scheme = signatureScheme(key)
        const data = Buffer.from(message, 'utf8')
        const signature = crypto.sign(scheme.digest, data, { key, ...scheme.options })

        return {
            output: signature.toString('base64'),
            signature: signature.toString('base64'),
            publicKey: crypto.createPublicKey(key).export({ type: 'spki', format: 'pem' }),
            details: {
                algorithm: scheme.name,
                ...scheme.extra,
                messageBytes: data.length,
                signatureBytes: signature.length,
                encoding: 'base64'
            }
        }
    }

    function verify(message, signatureBase64, publicKeyPem) {
        requireText(message, 'Message')
        requireText(signatureBase64, 'Signature')
        requireText(publicKeyPem, 'Public key')

        const clean = signatureBase64.replace(/\s+/g, '')
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) {
            throw new CryptoInputError('Signature must be base64, as produced by Sign.')
        }
        const key = parseKey(publicKeyPem, 'public')
        const scheme = signatureScheme(key)
        const data = Buffer.from(message, 'utf8')
        const signature = Buffer.from(clean, 'base64')

        let valid
        try {
            valid = crypto.verify(scheme.digest, data, { key, ...scheme.options }, signature)
        } catch {
            valid = false // e.g. a signature of the wrong length for the key
        }

        return {
            verdict: valid ? 'valid' : 'invalid',
            output: valid
                ? 'Valid: this signature was made by the matching private key, over exactly this message.'
                : 'Invalid: the message, the signature or the key has changed since signing (or they never belonged together).',
            details: {
                algorithm: scheme.name,
                ...scheme.extra,
                valid,
                messageBytes: data.length,
                signatureBytes: signature.length
            }
        }
    }

    return { aesEncrypt, aesDecrypt, hash, rsaGenerateKeys, rsaEncrypt, rsaDecrypt, sigGenerateKeys, sign, verify }
}

// Changes one visible character of the message: the first ASCII letter or digit moves to the
// next one in its range (a->b, z->a, 9->0). Falls back to appending "!" if there is none.
function tamperMessage(message) {
    const index = message.search(/[A-Za-z0-9]/)
    if (index === -1) {
        return { value: message + '!', change: { part: 'message', position: message.length, from: '', to: '!' } }
    }
    const from = message[index]
    const ranges = ['az', 'AZ', '09'].find(([lo, hi]) => from >= lo && from <= hi)
    const to = from === ranges[1] ? ranges[0] : String.fromCharCode(from.charCodeAt(0) + 1)
    return {
        value: message.slice(0, index) + to + message.slice(index + 1),
        change: { part: 'message', position: index, from, to }
    }
}

// Flips the lowest bit of the middle byte of a base64 signature
function tamperSignature(signatureBase64) {
    const clean = signatureBase64.replace(/\s+/g, '')
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) throw new CryptoInputError('Signature must be base64, as produced by Sign.')
    const bytes = Buffer.from(clean, 'base64')
    const position = Math.floor(bytes.length / 2)
    const from = bytes[position]
    bytes[position] ^= 0x01
    return {
        value: bytes.toString('base64'),
        change: { part: 'signature', byte: position, from: `0x${from.toString(16).padStart(2, '0')}`, to: `0x${bytes[position].toString(16).padStart(2, '0')}` }
    }
}

module.exports = { createCryptoService, CryptoInputError, DEFAULT_SCRYPT, tamperMessage, tamperSignature }
