// Crypto Client - a local demo of AES encryption, SHA-512 hashing and RSA.
// createApp() builds the Express app; it only listens when this file is run directly.

const crypto = require('node:crypto')
const path = require('node:path')
const express = require('express')

const { createCryptoService } = require('./lib/cryptoService')
const { createSessionStore } = require('./lib/sessionStore')
const { loadConfig, bindingBadge } = require('./lib/config')
const { createCryptoController } = require('./controllers/cryptoController')

const SECURITY_HEADERS = {
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY'
}

// Rejects cross-site form posts (CSRF). Browsers send Origin on POST; non-browser clients
// such as curl usually don't, and are allowed through.
function sameOriginOnly(req, res, next) {
    if (req.method !== 'POST') return next()
    const origin = req.get('origin')
    let crossSite = req.get('sec-fetch-site') === 'cross-site'
    if (origin) {
        try {
            crossSite ||= new URL(origin).host !== req.get('host')
        } catch {
            crossSite = true
        }
    }
    if (!crossSite) return next()
    const err = new Error('Cross-site request blocked: this form must be submitted from the Crypto Client page itself.')
    err.status = 403
    next(err)
}

function createApp({
    cryptoService = createCryptoService(),
    sessionStore = createSessionStore(),
    config = loadConfig(),
    logger = console
} = {}) {
    const app = express()
    const badge = bindingBadge(config)

    app.disable('x-powered-by')
    app.set('views', path.join(__dirname, 'views'))
    app.set('view engine', 'ejs')

    app.use((req, res, next) => {
        req.id = crypto.randomUUID()
        res.set('X-Request-Id', req.id)
        res.set(SECURITY_HEADERS)
        next()
    })
    app.use('/assets', express.static(path.join(__dirname, 'public')))

    // Pages carry secrets and keys, so never cache them
    app.use((req, res, next) => {
        res.set('Cache-Control', 'no-store')
        next()
    })
    app.use(sameOriginOnly)
    app.use(express.urlencoded({ extended: false, limit: '64kb' }))
    app.use(sessionStore.middleware)
    app.use(createCryptoController({ cryptoService, badge }))

    app.use((req, res) => {
        res.status(404).render('error', { status: 404, title: 'Not Found', message: `No page at ${req.path}.`, requestId: req.id, badge })
    })

    // Express 5 forwards rejected promises from async handlers here
    // eslint-disable-next-line no-unused-vars
    app.use((err, req, res, next) => {
        const status = Number.isInteger(err.status) && err.status >= 400 && err.status < 600 ? err.status : 500
        const message = status === 500
            ? 'Something went wrong on the server. The request ID below matches the server log entry.'
            : err.expose === false ? 'The request could not be processed.' : err.message
        if (status === 500) logger.error(`[${req.id}] ${err.stack || err}`)
        res.status(status).render('error', { status, title: status === 500 ? 'Server Error' : 'Request Rejected', message, requestId: req.id, badge })
    })

    return app
}

module.exports = { createApp, sameOriginOnly }

if (require.main === module) {
    const config = loadConfig()
    createApp({ config }).listen(config.port, config.host, function () {
        const { address, port } = this.address()
        console.log(`Crypto Client listening on http://${address.includes(':') ? `[${address}]` : address}:${port}`)
    })
}
