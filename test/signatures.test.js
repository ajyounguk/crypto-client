const { test, describe, before } = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const request = require('supertest')

const { createApp } = require('../app')
const { createCryptoService, CryptoInputError, tamperMessage, tamperSignature } = require('../lib/cryptoService')
const { createSessionStore } = require('../lib/sessionStore')

const svc = createCryptoService({ scryptParams: { N: 1024, r: 8, p: 1 } })
const isInputError = message => err => err instanceof CryptoInputError && err.status === 400 && message.test(err.message)

describe('signature service', () => {
    let ed, rsa
    before(async () => {
        ed = await svc.sigGenerateKeys()
        rsa = await svc.rsaGenerateKeys()
    })

    test('generates an Ed25519 PEM key pair', () => {
        assert.match(ed.publicKey, /^-----BEGIN PUBLIC KEY-----\n/)
        assert.match(ed.privateKey, /^-----BEGIN PRIVATE KEY-----\n/)
        assert.equal(crypto.createPublicKey(ed.publicKey).asymmetricKeyType, 'ed25519')
        assert.equal(ed.details.algorithm, 'Ed25519')
    })

    test('Ed25519 sign and verify', () => {
        const s = svc.sign('pay alice £10', ed.privateKey)
        assert.equal(Buffer.from(s.output, 'base64').length, 64)
        assert.equal(s.details.algorithm, 'Ed25519')
        assert.equal(s.publicKey, ed.publicKey, 'public key derived from the private key')
        const v = svc.verify('pay alice £10', s.signature, ed.publicKey)
        assert.equal(v.verdict, 'valid')
        assert.equal(v.details.valid, true)
        assert.match(v.output, /^Valid/)
    })

    test('Ed25519 signatures are deterministic', () => {
        assert.equal(svc.sign('same', ed.privateKey).output, svc.sign('same', ed.privateKey).output)
    })

    test('RSA keys sign with RSA-PSS SHA-256', () => {
        const s = svc.sign('hello', rsa.privateKey)
        assert.equal(s.details.algorithm, 'RSA-PSS')
        assert.equal(s.details.hash, 'SHA-256')
        assert.equal(Buffer.from(s.output, 'base64').length, 256)
        assert.notEqual(s.output, svc.sign('hello', rsa.privateKey).output, 'PSS is randomised')
        assert.equal(svc.verify('hello', s.output, rsa.publicKey).verdict, 'valid')
        assert.equal(svc.verify('hellO', s.output, rsa.publicKey).verdict, 'invalid')
    })

    test('a changed message, signature or key is invalid', async () => {
        const s = svc.sign('original', ed.privateKey)
        assert.equal(svc.verify('original!', s.output, ed.publicKey).verdict, 'invalid')
        assert.equal(svc.verify('original', tamperSignature(s.output).value, ed.publicKey).verdict, 'invalid')
        const other = await svc.sigGenerateKeys()
        const v = svc.verify('original', s.output, other.publicKey)
        assert.equal(v.verdict, 'invalid')
        assert.match(v.output, /^Invalid/)
    })

    test('a signature of the wrong length or scheme is invalid, not a crash', () => {
        assert.equal(svc.verify('x', 'AAAA', ed.publicKey).verdict, 'invalid')
        assert.equal(svc.verify('x', 'AAAA', rsa.publicKey).verdict, 'invalid')
        const edSig = svc.sign('x', ed.privateKey).output
        assert.equal(svc.verify('x', edSig, rsa.publicKey).verdict, 'invalid')
    })

    test('rejects keys that cannot sign, and bad input', () => {
        const x = crypto.generateKeyPairSync('x25519')
        const xPriv = x.privateKey.export({ type: 'pkcs8', format: 'pem' })
        assert.throws(() => svc.sign('x', xPriv), isInputError(/Can't sign with a x25519 key/))
        assert.throws(() => svc.sign('x', 'nope'), isInputError(/Couldn't read the private key/))
        assert.throws(() => svc.verify('x', 'AAAA', 'nope'), isInputError(/Couldn't read the public key/))
        assert.throws(() => svc.verify('x', '***', ed.publicKey), isInputError(/must be base64/))
        assert.throws(() => svc.sign('', ed.privateKey), isInputError(/Message is required/))
        assert.throws(() => svc.verify('x', '', ed.publicKey), isInputError(/Signature is required/))
        assert.throws(() => svc.verify('x', 'AAAA', ''), isInputError(/Public key is required/))
    })

    test('tamperMessage changes exactly one visible character', () => {
        assert.deepEqual(tamperMessage('Hello'), { value: 'Iello', change: { part: 'message', position: 0, from: 'H', to: 'I' } })
        assert.equal(tamperMessage('£ zed').value, '£ aed')
        assert.equal(tamperMessage('Z').value, 'A')
        assert.equal(tamperMessage('-9-').value, '-0-')
        assert.deepEqual(tamperMessage('£€'), { value: '£€!', change: { part: 'message', position: 2, from: '', to: '!' } })
    })

    test('tamperSignature flips one bit of the middle byte', () => {
        const sig = Buffer.alloc(64, 0x10).toString('base64')
        const t = tamperSignature(sig)
        const before = Buffer.from(sig, 'base64')
        const after = Buffer.from(t.value, 'base64')
        assert.equal(after.length, 64)
        assert.deepEqual([...after.keys()].filter(i => before[i] !== after[i]), [32])
        assert.deepEqual(t.change, { part: 'signature', byte: 32, from: '0x10', to: '0x11' })
        assert.throws(() => tamperSignature('***'), isInputError(/must be base64/))
    })
})

// ---- Routes ----

const decode = s => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#34;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&')
function fieldValue(html, id) {
    const ta = html.match(new RegExp(`<textarea[^>]*id="${id}"[^>]*>([\\s\\S]*?)</textarea>`))
    assert.ok(ta, `no textarea with id ${id}`)
    return decode(ta[1])
}
const responseOutput = html => decode(html.match(/<pre id="response-output"[^>]*>([\s\S]*?)<\/pre>/)[1])
const statusBadge = html => html.match(/class="status-badge[^"]*">([^<]*)</)?.[1]
const verdict = html => html.match(/class="verdict verdict-(\w+)">([^<]*)</)?.slice(1)

async function submit(agent, path, form) {
    const post = await agent.post(path).type('form').send(form)
    assert.equal(post.status, 303, `POST ${path} should redirect`)
    const page = await agent.get(post.headers.location)
    return { location: post.headers.location, html: page.text }
}

const newAgent = () => request.agent(createApp({
    cryptoService: svc,
    sessionStore: createSessionStore(),
    config: { host: '127.0.0.1', port: 3000 },
    logger: { error() {} }
}))

async function signedAgent(message = 'Ship release 42') {
    const agent = newAgent()
    const keys = await submit(agent, '/sigKeys', {})
    const signed = await submit(agent, '/sign', { data: message, priv: fieldValue(keys.html, 'sig-key-priv') })
    const tab = (await agent.get('/?tab=verify')).text
    const form = { data: fieldValue(tab, 'verify-data'), signature: fieldValue(tab, 'verify-signature'), pub: fieldValue(tab, 'verify-pub') }
    return { agent, keys, signed, form }
}

describe('signature routes', () => {
    test('key generation pre-fills Sign and Verify', async () => {
        const agent = newAgent()
        const { location, html } = await submit(agent, '/sigKeys', {})
        assert.equal(location, '/?tab=sig-keys')
        assert.match(fieldValue(html, 'sig-key-pub'), /^-----BEGIN PUBLIC KEY-----/)
        assert.match(html, /&#34;algorithm&#34;: &#34;Ed25519&#34;/)
        assert.match(html, /data-confirm="Replace the current signing key pair\?/)
        assert.equal(fieldValue((await agent.get('/?tab=sign')).text, 'sign-priv'), fieldValue(html, 'sig-key-priv'))
        assert.equal(fieldValue((await agent.get('/?tab=verify')).text, 'verify-pub'), fieldValue(html, 'sig-key-pub'))
    })

    test('sign pre-fills Verify, which reports VALID', async () => {
        const { agent, keys, signed, form } = await signedAgent()
        assert.equal(signed.location, '/?tab=sign')
        const signature = responseOutput(signed.html)
        assert.equal(Buffer.from(signature, 'base64').length, 64)
        assert.deepEqual(form, { data: 'Ship release 42', signature, pub: fieldValue(keys.html, 'sig-key-pub') })

        const { location, html } = await submit(agent, '/verify', form)
        assert.equal(location, '/?tab=verify')
        assert.equal(statusBadge(html), '200 OK')
        assert.deepEqual(verdict(html), ['valid', '✓ VALID'])
        assert.match(html, /class="response is-ok"/)
        assert.doesNotMatch(html, /tamper-note/)
    })

    test('tamper message: one character changes, stays in the form, INVALID', async () => {
        const { agent, form } = await signedAgent()
        const { html } = await submit(agent, '/verify', { ...form, tamper: 'message' })
        assert.deepEqual(verdict(html), ['invalid', '✗ INVALID'])
        assert.match(html, /class="response is-invalid"/)
        assert.equal(fieldValue(html, 'verify-data'), 'Thip release 42')
        assert.match(html, /message character 1 changed <code>S<\/code> → <code>T<\/code>/)
        assert.match(html, /&#34;tampered&#34;/)

        const again = await submit(agent, '/verify', { ...form, data: 'Thip release 42' })
        assert.equal(verdict(again.html)[0], 'invalid', 'the tampered message stays invalid')
    })

    test('tamper signature: one bit flips, INVALID', async () => {
        const { agent, form } = await signedAgent()
        const { html } = await submit(agent, '/verify', { ...form, tamper: 'signature' })
        assert.equal(verdict(html)[0], 'invalid')
        assert.notEqual(fieldValue(html, 'verify-signature'), form.signature)
        assert.match(html, /signature byte 32 changed <code>0x[0-9a-f]{2}<\/code> → <code>0x[0-9a-f]{2}<\/code> \(one bit flipped\)/)
    })

    test('RSA keys from the RSA Keys tab can sign too', async () => {
        const agent = newAgent()
        const rsa = await submit(agent, '/rsaKeys', {})
        const signed = await submit(agent, '/sign', { data: 'hi', priv: fieldValue(rsa.html, 'rsa-key-priv') })
        assert.match(signed.html, /&#34;RSA-PSS&#34;/)
        const tab = (await agent.get('/?tab=verify')).text
        assert.equal(fieldValue(tab, 'verify-pub'), fieldValue(rsa.html, 'rsa-key-pub'))
        const v = await submit(agent, '/verify', { data: 'hi', signature: responseOutput(signed.html), pub: fieldValue(tab, 'verify-pub') })
        assert.equal(verdict(v.html)[0], 'valid')
    })

    test('bad input is a 400 result with no verdict', async () => {
        const agent = newAgent()
        let { html } = await submit(agent, '/sign', { data: 'x', priv: 'garbage' })
        assert.equal(statusBadge(html), '400 Bad Request')
        assert.equal(verdict(html), undefined)
        ;({ html } = await submit(agent, '/verify', { data: 'x', signature: '***', pub: 'garbage', tamper: 'signature' }))
        assert.equal(statusBadge(html), '400 Bad Request')
        assert.match(responseOutput(html), /must be base64/)
        assert.equal(verdict(html), undefined)
    })

    test('regenerating signing keys clears stale Sign/Verify results', async () => {
        const { agent } = await signedAgent()
        await submit(agent, '/sigKeys', {})
        assert.doesNotMatch((await agent.get('/?tab=sign')).text, /class="response/)
        assert.equal(fieldValue((await agent.get('/?tab=verify')).text, 'verify-signature'), '')
    })

    test('escapes hostile input on Sign and Verify', async () => {
        const agent = newAgent()
        const SCRIPT = '<script>alert(1)</script>'
        const pages = [
            (await submit(agent, '/sign', { data: SCRIPT, priv: SCRIPT })).html,
            (await submit(agent, '/verify', { data: SCRIPT, signature: 'AAAA', pub: SCRIPT, tamper: 'message' })).html
        ]
        for (const html of pages) {
            assert.doesNotMatch(html, /<script>alert/)
            assert.match(html, /&lt;script&gt;/)
        }
    })
})
