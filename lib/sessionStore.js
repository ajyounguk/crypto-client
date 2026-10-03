// Minimal in-memory, per-browser session store.
//
// The original app kept one global object for every visitor, so one person's plaintext, secrets
// and private keys were shown to the next. Each browser now gets a random session id cookie and
// its own state. State lives only in this process's memory and expires after `ttlMs` idle.

const crypto = require('node:crypto')

const COOKIE_NAME = 'cc_sid'
const SID_PATTERN = /^[A-Za-z0-9_-]{43}$/

function emptyState() {
    return {
        forms: {
            aesEncrypt: { data: '', secret: '' },
            aesDecrypt: { cipher: '', secret: '' },
            hash: { data: '', secret: '' },
            rsaKeys: { publicKey: '', privateKey: '' },
            rsaEncrypt: { data: '', pub: '' },
            rsaDecrypt: { cipher: '', priv: '' }
        },
        results: {}
    }
}

function readCookie(header, name) {
    if (!header) return undefined
    for (const part of header.split(';')) {
        const eq = part.indexOf('=')
        if (eq > 0 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim()
    }
    return undefined
}

function createSessionStore({ ttlMs = 30 * 60 * 1000, maxSessions = 1000, now = Date.now } = {}) {
    const sessions = new Map()

    function pruneExpired() {
        const cutoff = now() - ttlMs
        for (const [sid, entry] of sessions) {
            if (entry.lastSeen < cutoff) sessions.delete(sid)
        }
    }

    function touch(sid, entry) {
        entry.lastSeen = now()
        sessions.delete(sid)
        sessions.set(sid, entry)
        // Map iterates in insertion order and touch() re-inserts, so the first key is the least recently used
        while (sessions.size > maxSessions) sessions.delete(sessions.keys().next().value)
    }

    // Express middleware: attaches req.session (the state object) and req.resetSession()
    function middleware(req, res, next) {
        pruneExpired()
        let sid = readCookie(req.headers.cookie, COOKIE_NAME)
        let entry = sid && SID_PATTERN.test(sid) ? sessions.get(sid) : undefined

        if (!entry) {
            sid = crypto.randomBytes(32).toString('base64url')
            entry = { state: emptyState() }
            res.cookie(COOKIE_NAME, sid, { httpOnly: true, sameSite: 'strict', path: '/' })
        }
        touch(sid, entry)

        req.session = entry.state
        req.resetSession = () => {
            entry.state = emptyState()
            req.session = entry.state
        }
        next()
    }

    return { middleware, size: () => sessions.size }
}

module.exports = { createSessionStore, emptyState, readCookie, COOKIE_NAME }
