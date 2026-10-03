// Routes for the crypto demo.
//
// Every POST runs one operation, stores the submitted form values and the result in the
// caller's session, then 303-redirects to GET /?tab=<op> (post/redirect/get), so a browser
// refresh never re-submits a form.

const express = require('express')
const { CryptoInputError, tamperMessage, tamperSignature } = require('../lib/cryptoService')

const OPS = [
    { id: 'aes-encrypt', path: '/encrypt', label: 'AES Encrypt', group: 'Symmetric' },
    { id: 'aes-decrypt', path: '/decrypt', label: 'AES Decrypt', group: 'Symmetric' },
    { id: 'hash', path: '/hash', label: 'SHA-512 Hash', group: 'Hashing' },
    { id: 'rsa-keys', path: '/rsaKeys', label: 'RSA Keys', group: 'Asymmetric' },
    { id: 'rsa-encrypt', path: '/rsaEncrypt', label: 'RSA Encrypt', group: 'Asymmetric' },
    { id: 'rsa-decrypt', path: '/rsaDecrypt', label: 'RSA Decrypt', group: 'Asymmetric' },
    { id: 'sig-keys', path: '/sigKeys', label: 'Signing Keys', group: 'Signatures' },
    { id: 'sign', path: '/sign', label: 'Sign', group: 'Signatures' },
    { id: 'verify', path: '/verify', label: 'Verify', group: 'Signatures' }
]
const OP_IDS = new Set(OPS.map(op => op.id))
const DEFAULT_TAB = OPS[0].id

const STATUS_TEXT = { 200: 'OK', 400: 'Bad Request', 500: 'Internal Server Error' }

function field(body, name) {
    const value = body?.[name]
    return typeof value === 'string' ? value : ''
}

function createCryptoController({ cryptoService, badge }) {
    const router = express.Router()

    // Runs an operation and records the outcome. Input errors become a 400 result shown in the
    // response panel; anything else is a bug and goes to the app's 500 handler.
    // `onSuccess(value)` updates other forms' pre-fills before the redirect is sent.
    async function run(req, res, opId, fn, onSuccess) {
        const started = process.hrtime.bigint()
        let result
        try {
            const value = await fn()
            result = { ok: true, status: 200, output: value.output, details: value.details, verdict: value.verdict }
            onSuccess?.(value)
        } catch (err) {
            if (!(err instanceof CryptoInputError)) throw err
            result = { ok: false, status: err.status, output: err.message, details: { error: err.name, message: err.message } }
        }
        result.statusText = STATUS_TEXT[result.status]
        result.requestId = req.id
        result.durationMs = Number((process.hrtime.bigint() - started) / 1000n) / 1000
        req.session.results[opId] = result
        res.redirect(303, `/?tab=${opId}`)
    }

    router.get('/', (req, res) => {
        const tab = OP_IDS.has(req.query.tab) ? req.query.tab : DEFAULT_TAB
        res.render('index', {
            ops: OPS,
            active: OPS.find(op => op.id === tab),
            forms: req.session.forms,
            result: req.session.results[tab],
            badge
        })
    })

    router.post('/encrypt', async (req, res) => {
        const form = req.session.forms.aesEncrypt
        form.data = field(req.body, 'data')
        form.secret = field(req.body, 'secret')
        await run(req, res, 'aes-encrypt', () => cryptoService.aesEncrypt(form.data, form.secret), ({ output }) => {
            // Pre-fill AES Decrypt so the round trip is one click away
            req.session.forms.aesDecrypt = { cipher: output, secret: form.secret }
        })
    })

    router.post('/decrypt', async (req, res) => {
        const form = req.session.forms.aesDecrypt
        form.cipher = field(req.body, 'cipher')
        form.secret = field(req.body, 'secret')
        await run(req, res, 'aes-decrypt', () => cryptoService.aesDecrypt(form.cipher, form.secret))
    })

    router.post('/hash', async (req, res) => {
        const form = req.session.forms.hash
        form.data = field(req.body, 'data')
        form.secret = field(req.body, 'secret')
        await run(req, res, 'hash', () => cryptoService.hash(form.data, form.secret))
    })

    router.post('/rsaKeys', async (req, res) => {
        await run(req, res, 'rsa-keys', () => cryptoService.rsaGenerateKeys(), keys => {
            const forms = req.session.forms
            forms.rsaKeys = { publicKey: keys.publicKey, privateKey: keys.privateKey }
            forms.rsaEncrypt.pub = keys.publicKey
            forms.rsaDecrypt = { cipher: '', priv: keys.privateKey }
            delete req.session.results['rsa-encrypt']
            delete req.session.results['rsa-decrypt']
        })
    })

    router.post('/rsaEncrypt', async (req, res) => {
        const form = req.session.forms.rsaEncrypt
        form.data = field(req.body, 'data')
        form.pub = field(req.body, 'pub')
        await run(req, res, 'rsa-encrypt', () => cryptoService.rsaEncrypt(form.data, form.pub), ({ output }) => {
            req.session.forms.rsaDecrypt.cipher = output
            delete req.session.results['rsa-decrypt']
        })
    })

    router.post('/rsaDecrypt', async (req, res) => {
        const form = req.session.forms.rsaDecrypt
        form.cipher = field(req.body, 'cipher')
        form.priv = field(req.body, 'priv')
        await run(req, res, 'rsa-decrypt', () => cryptoService.rsaDecrypt(form.cipher, form.priv))
    })

    router.post('/sigKeys', async (req, res) => {
        await run(req, res, 'sig-keys', () => cryptoService.sigGenerateKeys(), keys => {
            const forms = req.session.forms
            forms.sigKeys = { publicKey: keys.publicKey, privateKey: keys.privateKey }
            forms.sign.priv = keys.privateKey
            forms.verify = { data: '', signature: '', pub: keys.publicKey }
            delete req.session.results.sign
            delete req.session.results.verify
        })
    })

    router.post('/sign', async (req, res) => {
        const form = req.session.forms.sign
        form.data = field(req.body, 'data')
        form.priv = field(req.body, 'priv')
        await run(req, res, 'sign', () => cryptoService.sign(form.data, form.priv), ({ signature, publicKey }) => {
            // Pre-fill Verify with the message, signature and the public half of the signing key
            req.session.forms.verify = { data: form.data, signature, pub: publicKey }
            delete req.session.results.verify
        })
    })

    // `tamper` = 'message' | 'signature' changes one character/bit before verifying, and the
    // tampered value is kept in the form so the user can see exactly what changed
    router.post('/verify', async (req, res) => {
        const form = req.session.forms.verify
        form.data = field(req.body, 'data')
        form.signature = field(req.body, 'signature')
        form.pub = field(req.body, 'pub')
        const tamper = field(req.body, 'tamper')

        await run(req, res, 'verify', () => {
            let change
            if (tamper === 'message' && form.data) ({ value: form.data, change } = tamperMessage(form.data))
            if (tamper === 'signature' && form.signature) ({ value: form.signature, change } = tamperSignature(form.signature))
            const value = cryptoService.verify(form.data, form.signature, form.pub)
            if (change) value.details = { tampered: change, ...value.details }
            return value
        })
    })

    // Clears everything this browser has entered or generated
    router.post('/reset', (req, res) => {
        req.resetSession()
        res.redirect(303, '/')
    })

    return router
}

module.exports = { createCryptoController, OPS }
