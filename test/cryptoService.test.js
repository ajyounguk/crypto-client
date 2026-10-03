const { test, describe, before } = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')

const { createCryptoService, CryptoInputError } = require('../lib/cryptoService')

// Cheap scrypt cost keeps the suite fast; the real default is N=16384
const svc = createCryptoService({ scryptParams: { N: 1024, r: 8, p: 1 } })

const isInputError = message => err => err instanceof CryptoInputError && err.status === 400 && message.test(err.message)

describe('AES-256-GCM', () => {
    test('round trips text, including non-ASCII', async () => {
        const text = 'Hello, wörld ✓ 🔐'
        const enc = await svc.aesEncrypt(text, 'correct horse')
        assert.match(enc.output, /^[0-9a-f]+$/)
        assert.equal(enc.details.algorithm, 'aes-256-gcm')
        assert.equal(enc.details.kdf.name, 'scrypt')
        assert.equal(enc.output.length, (16 + 12 + 16 + Buffer.byteLength(text)) * 2)

        const dec = await svc.aesDecrypt(enc.output, 'correct horse')
        assert.equal(dec.output, text)
        assert.equal(dec.details.authenticated, true)
    })

    test('uses a fresh salt and IV each time', async () => {
        const a = await svc.aesEncrypt('same', 'secret')
        const b = await svc.aesEncrypt('same', 'secret')
        assert.notEqual(a.output, b.output)
    })

    test('tolerates whitespace and upper-case hex in pasted cipher text', async () => {
        const enc = await svc.aesEncrypt('wrapped', 'k')
        const pasted = enc.output.toUpperCase().replace(/(.{32})/g, '$1\n ')
        assert.equal((await svc.aesDecrypt(pasted, 'k')).output, 'wrapped')
    })

    test('rejects the wrong secret', async () => {
        const enc = await svc.aesEncrypt('top secret', 'right')
        await assert.rejects(svc.aesDecrypt(enc.output, 'wrong'), isInputError(/wrong secret/))
    })

    test('detects tampering via the auth tag', async () => {
        const enc = await svc.aesEncrypt('pay alice 10', 'k')
        const last = enc.output.slice(-2)
        const flipped = enc.output.slice(0, -2) + (parseInt(last, 16) ^ 1).toString(16).padStart(2, '0')
        await assert.rejects(svc.aesDecrypt(flipped, 'k'), isInputError(/modified/))
    })

    test('rejects non-hex, odd-length and truncated cipher text', async () => {
        await assert.rejects(svc.aesDecrypt('not hex!', 'k'), isInputError(/must be hex/))
        await assert.rejects(svc.aesDecrypt('abc', 'k'), isInputError(/must be hex/))
        await assert.rejects(svc.aesDecrypt('00'.repeat(44), 'k'), isInputError(/too short/))
    })

    test('requires plaintext, cipher text and secret', async () => {
        await assert.rejects(svc.aesEncrypt('', 'k'), isInputError(/Plaintext is required/))
        await assert.rejects(svc.aesEncrypt('x', ''), isInputError(/Secret is required/))
        await assert.rejects(svc.aesDecrypt('', 'k'), isInputError(/Cipher text is required/))
        await assert.rejects(svc.aesEncrypt(undefined, 'k'), isInputError(/Plaintext is required/))
    })
})

describe('SHA-512 / HMAC-SHA-512', () => {
    test('plain SHA-512 when no secret is given (FIPS 180-2 "abc" vector)', () => {
        const r = svc.hash('abc')
        assert.equal(r.output, 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f')
        assert.deepEqual(r.details, { algorithm: 'SHA-512', keyed: false, inputBytes: 3, outputBits: 512 })
        assert.equal(svc.hash('abc', '').output, r.output)
    })

    test('HMAC-SHA-512 when a secret is given (RFC 4231 test case 2)', () => {
        const r = svc.hash('what do ya want for nothing?', 'Jefe')
        assert.equal(r.output, '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737')
        assert.equal(r.details.algorithm, 'HMAC-SHA-512')
    })

    test('requires plaintext', () => {
        assert.throws(() => svc.hash(''), isInputError(/Plaintext is required/))
    })
})

describe('RSA', () => {
    let keys
    before(async () => { keys = await svc.rsaGenerateKeys() })

    test('generates a 2048-bit PEM key pair', () => {
        assert.match(keys.publicKey, /^-----BEGIN PUBLIC KEY-----\n/)
        assert.match(keys.privateKey, /^-----BEGIN PRIVATE KEY-----\n/)
        assert.equal(keys.output, keys.publicKey)
        assert.equal(crypto.createPublicKey(keys.publicKey).asymmetricKeyDetails.modulusLength, 2048)
        assert.equal(keys.details.maxOaepPlaintextBytes, 190)
    })

    test('round trips with OAEP-SHA-256', () => {
        const enc = svc.rsaEncrypt('meet at noon', keys.publicKey)
        assert.equal(Buffer.from(enc.output, 'base64').length, 256)
        assert.equal(enc.details.algorithm, 'RSA-OAEP')
        assert.equal(svc.rsaDecrypt(enc.output, keys.privateKey).output, 'meet at noon')
    })

    test('enforces the OAEP plaintext size limit', () => {
        assert.doesNotThrow(() => svc.rsaEncrypt('x'.repeat(190), keys.publicKey))
        assert.throws(() => svc.rsaEncrypt('x'.repeat(191), keys.publicKey), isInputError(/191 bytes.*at most 190/))
    })

    test('rejects malformed and non-RSA keys', () => {
        assert.throws(() => svc.rsaEncrypt('hi', 'not a key'), isInputError(/Couldn't read the public key/))
        assert.throws(() => svc.rsaDecrypt('AAAA', 'not a key'), isInputError(/Couldn't read the private key/))
        const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
        const ecPub = ec.publicKey.export({ type: 'spki', format: 'pem' })
        const ecPriv = ec.privateKey.export({ type: 'pkcs8', format: 'pem' })
        assert.throws(() => svc.rsaEncrypt('hi', ecPub), isInputError(/Expected an RSA key, got ec/))
        assert.throws(() => svc.rsaDecrypt('AAAA', ecPriv), isInputError(/Expected an RSA key, got ec/))
    })

    test('rejects the wrong private key and bad base64', async () => {
        const other = await svc.rsaGenerateKeys()
        const enc = svc.rsaEncrypt('hi', keys.publicKey)
        assert.throws(() => svc.rsaDecrypt(enc.output, other.privateKey), isInputError(/doesn't match/))
        assert.throws(() => svc.rsaDecrypt('***', keys.privateKey), isInputError(/must be base64/))
    })

    test('requires all inputs', () => {
        assert.throws(() => svc.rsaEncrypt('', keys.publicKey), isInputError(/Plaintext is required/))
        assert.throws(() => svc.rsaEncrypt('x', ''), isInputError(/Public key is required/))
        assert.throws(() => svc.rsaDecrypt('', keys.privateKey), isInputError(/Cipher text is required/))
        assert.throws(() => svc.rsaDecrypt('AAAA', ''), isInputError(/Private key is required/))
    })
})
