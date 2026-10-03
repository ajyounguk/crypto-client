const { test, describe } = require('node:test')
const assert = require('node:assert/strict')

const { createSessionStore, readCookie, emptyState, COOKIE_NAME } = require('../lib/sessionStore')

// Runs the middleware against a fake request and returns { req, setCookie }
function call(store, cookieHeader) {
    const req = { headers: { cookie: cookieHeader } }
    let setCookie
    const res = { cookie: (name, value, opts) => { setCookie = { name, value, opts } } }
    store.middleware(req, res, () => {})
    return { req, setCookie }
}

describe('readCookie', () => {
    test('finds a named cookie among others', () => {
        assert.equal(readCookie('a=1; cc_sid=abc; b=2', 'cc_sid'), 'abc')
        assert.equal(readCookie('cc_sid_other=x', 'cc_sid'), undefined)
        assert.equal(readCookie(undefined, 'cc_sid'), undefined)
    })
})

describe('session store', () => {
    test('issues a new HttpOnly, SameSite=Strict cookie with empty state', () => {
        const store = createSessionStore()
        const { req, setCookie } = call(store)
        assert.equal(setCookie.name, COOKIE_NAME)
        assert.match(setCookie.value, /^[A-Za-z0-9_-]{43}$/)
        assert.deepEqual(setCookie.opts, { httpOnly: true, sameSite: 'strict', path: '/' })
        assert.deepEqual(req.session, emptyState())
    })

    test('returns the same state for the same cookie', () => {
        const store = createSessionStore()
        const first = call(store)
        first.req.session.forms.hash.data = 'remember me'
        const second = call(store, `${COOKIE_NAME}=${first.setCookie.value}`)
        assert.equal(second.setCookie, undefined)
        assert.equal(second.req.session.forms.hash.data, 'remember me')
    })

    test('ignores unknown or malformed session ids', () => {
        const store = createSessionStore()
        const { setCookie } = call(store, `${COOKIE_NAME}=../../etc`)
        assert.ok(setCookie)
        assert.ok(call(store, `${COOKIE_NAME}=${'A'.repeat(43)}`).setCookie)
    })

    test('resetSession replaces the state', () => {
        const store = createSessionStore()
        const { req, setCookie } = call(store)
        req.session.results.hash = { ok: true }
        req.resetSession()
        assert.deepEqual(req.session, emptyState())
        assert.deepEqual(call(store, `${COOKIE_NAME}=${setCookie.value}`).req.session, emptyState())
    })

    test('expires idle sessions after the TTL', () => {
        let clock = 0
        const store = createSessionStore({ ttlMs: 1000, now: () => clock })
        const { setCookie } = call(store)
        clock = 999
        assert.equal(call(store, `${COOKIE_NAME}=${setCookie.value}`).setCookie, undefined)
        clock = 2000
        assert.ok(call(store, `${COOKIE_NAME}=${setCookie.value}`).setCookie, 'expired session should be replaced')
    })

    test('caps the number of sessions, evicting the least recently used', () => {
        const store = createSessionStore({ maxSessions: 2 })
        const a = call(store).setCookie.value
        call(store)
        call(store, `${COOKIE_NAME}=${a}`) // touch a so it is most recent
        call(store) // third session evicts the oldest (the second)
        assert.equal(store.size(), 2)
        assert.equal(call(store, `${COOKIE_NAME}=${a}`).setCookie, undefined)
    })
})
