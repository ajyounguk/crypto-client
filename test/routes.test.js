const { test, describe, before } = require('node:test')
const assert = require('node:assert/strict')
const request = require('supertest')

const { createApp } = require('../app')
const { createCryptoService } = require('../lib/cryptoService')
const { createSessionStore } = require('../lib/sessionStore')

const fastCrypto = createCryptoService({ scryptParams: { N: 1024, r: 8, p: 1 } })
const TABS = ['aes-encrypt', 'aes-decrypt', 'hash', 'rsa-keys', 'rsa-encrypt', 'rsa-decrypt', 'sig-keys', 'sign', 'verify']

function makeApp(overrides = {}) {
    const logged = []
    const app = createApp({
        cryptoService: fastCrypto,
        sessionStore: createSessionStore(),
        config: { host: '127.0.0.1', port: 3000 },
        logger: { error: msg => logged.push(msg) },
        ...overrides
    })
    return { app, logged }
}

const decode = s => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#34;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&')

// Value of the <textarea> or <input> with the given id, entity-decoded
function fieldValue(html, id) {
    const ta = html.match(new RegExp(`<textarea[^>]*id="${id}"[^>]*>([\\s\\S]*?)</textarea>`))
    if (ta) return decode(ta[1])
    const input = html.match(new RegExp(`<input[^>]*id="${id}"[^>]*>`))
    assert.ok(input, `no field with id ${id}`)
    return decode(input[0].match(/value="([^"]*)"/)[1])
}
const responseOutput = html => decode(html.match(/<pre id="response-output"[^>]*>([\s\S]*?)<\/pre>/)[1])
const statusBadge = html => html.match(/class="status-badge[^"]*">([^<]*)</)?.[1]

// POST a form and follow the 303 like a browser would; returns the rendered page
async function submit(agent, path, form) {
    const post = await agent.post(path).type('form').send(form)
    assert.equal(post.status, 303, `POST ${path} should redirect`)
    const page = await agent.get(post.headers.location)
    assert.equal(page.status, 200)
    return { location: post.headers.location, html: page.text, postRequestId: post.headers['x-request-id'] }
}

describe('page rendering', () => {
    const { app } = makeApp()

    test('GET / renders the AES Encrypt tab by default', async () => {
        const res = await request(app).get('/')
        assert.equal(res.status, 200)
        assert.match(res.headers['content-type'], /text\/html/)
        assert.match(res.text, /<h2 id="op-title">AES Encrypt<\/h2>/)
        assert.match(res.text, /href="\/\?tab=aes-encrypt" aria-current="page"/)
        assert.doesNotMatch(res.text, /class="response/, 'no response panel before any action')
    })

    test('every tab renders, with one current nav link and no duplicate ids', async () => {
        for (const tab of TABS) {
            const res = await request(app).get(`/?tab=${tab}`)
            assert.equal(res.status, 200, tab)
            assert.equal(res.text.match(/aria-current="page"/g).length, 1, tab)
            assert.match(res.text, new RegExp(`href="/\\?tab=${tab}" aria-current="page"`))
            const ids = [...res.text.matchAll(/\sid="([^"]+)"/g)].map(m => m[1])
            assert.deepEqual(ids, [...new Set(ids)], `duplicate ids on ${tab}`)
            for (const [, forId] of res.text.matchAll(/<label for="([^"]+)"/g)) {
                assert.ok(ids.includes(forId), `label for="${forId}" has no target on ${tab}`)
            }
        }
    })

    test('unknown tab falls back to the default', async () => {
        const res = await request(app).get('/?tab=../../etc/passwd')
        assert.equal(res.status, 200)
        assert.match(res.text, /<h2 id="op-title">AES Encrypt<\/h2>/)
    })

    test('sets security headers, no-store and a request id', async () => {
        const res = await request(app).get('/')
        assert.match(res.headers['content-security-policy'], /script-src 'self'/)
        assert.equal(res.headers['x-content-type-options'], 'nosniff')
        assert.equal(res.headers['x-frame-options'], 'DENY')
        // 'no-referrer' would make browsers send "Origin: null" on our own form posts, which the CSRF check blocks
        assert.equal(res.headers['referrer-policy'], 'same-origin')
        assert.equal(res.headers['cache-control'], 'no-store')
        assert.match(res.headers['x-request-id'], /^[0-9a-f-]{36}$/)
        assert.equal(res.headers['x-powered-by'], undefined)
        assert.match(res.headers['set-cookie'][0], /^cc_sid=[\w-]{43}; Path=\/; HttpOnly; SameSite=Strict$/)
    })

    test('has no inline script, so the CSP holds', async () => {
        const res = await request(app).get('/')
        assert.doesNotMatch(res.text, /<script(?![^>]*\bsrc=)[^>]*>/)
        assert.doesNotMatch(res.text, /\son[a-z]+=/i)
    })

    test('serves static assets', async () => {
        assert.equal((await request(app).get('/assets/styles.css')).status, 200)
        assert.equal((await request(app).get('/assets/app.js')).status, 200)
    })

    test('shows the binding badge', async () => {
        assert.match((await request(app).get('/')).text, /env-badge env-local[^>]*>[\s\S]*Local only · 127\.0\.0\.1:3000/)
        const exposed = makeApp({ config: { host: '0.0.0.0', port: 8080 } }).app
        assert.match((await request(exposed).get('/')).text, /env-badge env-exposed[^>]*>[\s\S]*All interfaces · 0\.0\.0\.0:8080/)
    })

    test('unknown paths get a 404 page', async () => {
        const res = await request(app).get('/nope')
        assert.equal(res.status, 404)
        assert.match(res.text, /No page at \/nope/)
        assert.match(res.text, new RegExp(res.headers['x-request-id']))
    })
})

describe('AES routes', () => {
    test('encrypt redirects (303), shows the result and pre-fills decrypt', async () => {
        const agent = request.agent(makeApp().app)
        const { location, html, postRequestId } = await submit(agent, '/encrypt', { data: 'hello', secret: 's3cret' })
        assert.equal(location, '/?tab=aes-encrypt')
        assert.equal(statusBadge(html), '200 OK')
        assert.equal(fieldValue(html, 'aes-enc-data'), 'hello')
        assert.equal(fieldValue(html, 'aes-enc-secret'), 's3cret')
        const cipher = responseOutput(html)
        assert.match(cipher, /^[0-9a-f]{98}$/)
        assert.match(html, /&#34;algorithm&#34;: &#34;aes-256-gcm&#34;/)
        assert.match(html, new RegExp(`Request ID <code>${postRequestId}</code>`), 'footer shows the POST request id')

        const dec = await agent.get('/?tab=aes-decrypt')
        assert.equal(fieldValue(dec.text, 'aes-dec-cipher'), cipher)
        assert.equal(fieldValue(dec.text, 'aes-dec-secret'), 's3cret')
        assert.doesNotMatch(dec.text, /class="response/, 'decrypt tab has no result yet')
    })

    test('full round trip through the forms', async () => {
        const agent = request.agent(makeApp().app)
        const enc = await submit(agent, '/encrypt', { data: 'round trip ✓', secret: 'k' })
        const dec = await submit(agent, '/decrypt', { cipher: responseOutput(enc.html), secret: 'k' })
        assert.equal(dec.location, '/?tab=aes-decrypt')
        assert.equal(statusBadge(dec.html), '200 OK')
        assert.equal(responseOutput(dec.html), 'round trip ✓')
    })

    test('decrypt keeps what the user submitted, not the encrypt values', async () => {
        const agent = request.agent(makeApp().app)
        await submit(agent, '/encrypt', { data: 'a', secret: 'one' })
        const { html } = await submit(agent, '/decrypt', { cipher: 'abcd', secret: 'two' })
        assert.equal(fieldValue(html, 'aes-dec-cipher'), 'abcd')
        assert.equal(fieldValue(html, 'aes-dec-secret'), 'two')
    })

    test('wrong secret shows a 400 error result instead of crashing', async () => {
        const agent = request.agent(makeApp().app)
        const enc = await submit(agent, '/encrypt', { data: 'x', secret: 'right' })
        const { html } = await submit(agent, '/decrypt', { cipher: responseOutput(enc.html), secret: 'wrong' })
        assert.equal(statusBadge(html), '400 Bad Request')
        assert.match(html, /class="response is-error"/)
        assert.match(responseOutput(html), /wrong secret/)
    })

    test('missing fields are a 400 result', async () => {
        const agent = request.agent(makeApp().app)
        const { html } = await submit(agent, '/encrypt', { data: 'x' })
        assert.equal(statusBadge(html), '400 Bad Request')
        assert.match(responseOutput(html), /Secret is required/)
        const empty = await agent.post('/decrypt')
        assert.equal(empty.status, 303)
        assert.match(responseOutput((await agent.get('/?tab=aes-decrypt')).text), /Cipher text is required/)
    })
})

describe('hash route', () => {
    test('plain SHA-512 and HMAC', async () => {
        const agent = request.agent(makeApp().app)
        let { location, html } = await submit(agent, '/hash', { data: 'abc', secret: '' })
        assert.equal(location, '/?tab=hash')
        assert.match(responseOutput(html), /^ddaf35a193617aba/)
        assert.match(html, /&#34;SHA-512&#34;/);
        ({ html } = await submit(agent, '/hash', { data: 'what do ya want for nothing?', secret: 'Jefe' }))
        assert.match(responseOutput(html), /^164b7a7bfcf819e2/)
        assert.match(html, /&#34;HMAC-SHA-512&#34;/)
        assert.equal(fieldValue(html, 'hash-secret'), 'Jefe')
    })

    test('empty plaintext is a 400 result', async () => {
        const agent = request.agent(makeApp().app)
        const { html } = await submit(agent, '/hash', { data: '' })
        assert.equal(statusBadge(html), '400 Bad Request')
    })
})

describe('RSA routes', () => {
    let agent, keysPage
    before(async () => {
        agent = request.agent(makeApp().app)
        keysPage = await submit(agent, '/rsaKeys', {})
    })

    test('key generation shows both keys and pre-fills encrypt/decrypt', async () => {
        assert.equal(keysPage.location, '/?tab=rsa-keys')
        assert.equal(statusBadge(keysPage.html), '200 OK')
        const pub = fieldValue(keysPage.html, 'rsa-key-pub')
        const priv = fieldValue(keysPage.html, 'rsa-key-priv')
        assert.match(pub, /^-----BEGIN PUBLIC KEY-----/)
        assert.match(priv, /^-----BEGIN PRIVATE KEY-----/)
        assert.match(keysPage.html, /data-confirm="Replace the current key pair\?/)

        assert.equal(fieldValue((await agent.get('/?tab=rsa-encrypt')).text, 'rsa-enc-pub'), pub)
        assert.equal(fieldValue((await agent.get('/?tab=rsa-decrypt')).text, 'rsa-dec-priv'), priv)
    })

    test('encrypt then decrypt via the forms', async () => {
        const pub = fieldValue(keysPage.html, 'rsa-key-pub')
        const priv = fieldValue(keysPage.html, 'rsa-key-priv')
        const enc = await submit(agent, '/rsaEncrypt', { data: 'rsa works', pub })
        assert.equal(enc.location, '/?tab=rsa-encrypt')
        const cipher = responseOutput(enc.html)
        assert.match(cipher, /^[A-Za-z0-9+/]+={0,2}$/)

        const decTab = await agent.get('/?tab=rsa-decrypt')
        assert.equal(fieldValue(decTab.text, 'rsa-dec-cipher'), cipher, 'cipher pre-filled into decrypt')

        const dec = await submit(agent, '/rsaDecrypt', { cipher, priv })
        assert.equal(dec.location, '/?tab=rsa-decrypt')
        assert.equal(responseOutput(dec.html), 'rsa works')
    })

    test('bad key and oversized plaintext are 400 results', async () => {
        let { html } = await submit(agent, '/rsaEncrypt', { data: 'x', pub: 'garbage' })
        assert.equal(statusBadge(html), '400 Bad Request')
        assert.match(responseOutput(html), /Couldn't read the public key/)
        const pub = fieldValue(keysPage.html, 'rsa-key-pub');
        ({ html } = await submit(agent, '/rsaEncrypt', { data: 'x'.repeat(200), pub }))
        assert.match(responseOutput(html), /at most 190 bytes/);
        ({ html } = await submit(agent, '/rsaDecrypt', { cipher: 'AAAA', priv: 'garbage' }))
        assert.match(responseOutput(html), /Couldn't read the private key/)
    })

    test('regenerating keys clears stale RSA results', async () => {
        const a = request.agent(makeApp().app)
        const first = await submit(a, '/rsaKeys', {})
        await submit(a, '/rsaEncrypt', { data: 'hi', pub: fieldValue(first.html, 'rsa-key-pub') })
        await submit(a, '/rsaKeys', {})
        assert.doesNotMatch((await a.get('/?tab=rsa-encrypt')).text, /class="response/)
        assert.equal(fieldValue((await a.get('/?tab=rsa-decrypt')).text, 'rsa-dec-cipher'), '')
    })
})

describe('reset and sessions', () => {
    test('POST /reset clears the session and redirects to /', async () => {
        const agent = request.agent(makeApp().app)
        await submit(agent, '/hash', { data: 'forget me' })
        const res = await agent.post('/reset')
        assert.equal(res.status, 303)
        assert.equal(res.headers.location, '/')
        const page = await agent.get('/?tab=hash')
        assert.equal(fieldValue(page.text, 'hash-data'), '')
        assert.doesNotMatch(page.text, /class="response/)
    })

    test('reset button is red and asks for confirmation', async () => {
        const res = await request(makeApp().app).get('/')
        assert.match(res.text, /<form class="nav-reset" method="POST" action="\/reset" data-confirm="[^"]+">\s*<button type="submit" class="btn btn-danger/)
    })

    test('one browser never sees another browser\'s data', async () => {
        const { app } = makeApp()
        const alice = request.agent(app)
        const bob = request.agent(app)
        await submit(alice, '/encrypt', { data: 'alice private note', secret: 'alice-secret' })
        const bobPage = await bob.get('/?tab=aes-encrypt')
        assert.doesNotMatch(bobPage.text, /alice/)
        assert.doesNotMatch((await bob.get('/?tab=aes-decrypt')).text, /alice/)
    })
})

describe('cross-site request protection', () => {
    test('blocks a POST with a foreign Origin', async () => {
        const res = await request(makeApp().app).post('/encrypt').set('Origin', 'https://evil.example.com').type('form').send({ data: 'x', secret: 'y' })
        assert.equal(res.status, 403)
        assert.match(res.text, /Cross-site request blocked/)
    })

    test('blocks Sec-Fetch-Site: cross-site and a malformed Origin', async () => {
        const app = makeApp().app
        assert.equal((await request(app).post('/reset').set('Sec-Fetch-Site', 'cross-site')).status, 403)
        assert.equal((await request(app).post('/reset').set('Origin', 'null')).status, 403)
    })

    test('allows same-origin and Origin-less POSTs', async () => {
        const agent = request.agent(makeApp().app)
        assert.equal((await agent.post('/reset').set('Host', 'localhost:3000').set('Origin', 'http://localhost:3000')).status, 303)
        assert.equal((await agent.post('/reset').set('Host', 'localhost:3000').set('Origin', 'http://localhost:3001')).status, 403)
        assert.equal((await agent.post('/reset').set('Sec-Fetch-Site', 'same-origin')).status, 303)
        assert.equal((await agent.post('/reset')).status, 303)
    })
})

describe('error handling', () => {
    test('oversized bodies get a 413 page', async () => {
        const res = await request(makeApp().app).post('/hash').type('form').send({ data: 'x'.repeat(70 * 1024) })
        assert.equal(res.status, 413)
        assert.match(res.text, /class="status-badge status-error">413/)
    })

    test('unexpected errors render a generic 500 with a request id and are logged', async () => {
        const boom = { ...fastCrypto, hash: () => { throw new Error('internal detail: /secret/path') } }
        const { app, logged } = makeApp({ cryptoService: boom })
        const res = await request(app).post('/hash').type('form').send({ data: 'x' })
        assert.equal(res.status, 500)
        assert.match(res.text, /Something went wrong on the server/)
        assert.doesNotMatch(res.text, /internal detail|at .*\.js:\d+/, 'no message or stack leaked to the page')
        assert.match(res.text, new RegExp(res.headers['x-request-id']))
        assert.equal(logged.length, 1)
        assert.match(logged[0], new RegExp(`^\\[${res.headers['x-request-id']}\\] Error: internal detail`))
    })

    test('async failures (rejected promises) also reach the 500 handler', async () => {
        const boom = { ...fastCrypto, rsaGenerateKeys: async () => { throw new TypeError('kaboom') } }
        const res = await request(makeApp({ cryptoService: boom }).app).post('/rsaKeys')
        assert.equal(res.status, 500)
    })
})

describe('output escaping (XSS)', () => {
    const SCRIPT = '<script>alert(1)</script>'
    const ATTR = '"><img src=x onerror=alert(1)>'

    test('user input is escaped in textareas, attributes and results', async () => {
        const agent = request.agent(makeApp().app)
        const pages = [
            (await submit(agent, '/encrypt', { data: SCRIPT, secret: ATTR })).html,
            (await agent.get('/?tab=aes-decrypt')).text,
            (await submit(agent, '/hash', { data: SCRIPT, secret: ATTR })).html,
            (await submit(agent, '/rsaEncrypt', { data: SCRIPT, pub: ATTR })).html,
            (await submit(agent, '/rsaDecrypt', { cipher: SCRIPT, priv: ATTR })).html
        ]
        for (const html of pages) {
            assert.doesNotMatch(html, /<script>alert/)
            assert.doesNotMatch(html, /<img src=x/)
            assert.doesNotMatch(html, /value=""><img/)
        }
        assert.match(pages[0], /&lt;script&gt;alert\(1\)&lt;\/script&gt;/)
        assert.match(pages[0], /value="&#34;&gt;&lt;img src=x onerror=alert\(1\)&gt;"/)
        assert.equal(fieldValue(pages[0], 'aes-enc-data'), SCRIPT, 'escaped value still round-trips')

        const dec = await submit(agent, '/decrypt', { cipher: responseOutput(pages[0]), secret: ATTR })
        assert.equal(responseOutput(dec.html), SCRIPT)
        assert.doesNotMatch(dec.html, /<script>alert/)
    })

    test('the 404 page escapes the path', async () => {
        const res = await request(makeApp().app).get('/%3Cscript%3Ealert(1)%3C%2Fscript%3E')
        assert.equal(res.status, 404)
        assert.doesNotMatch(res.text, /<script>alert/)
    })
})
