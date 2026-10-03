const { test, describe } = require('node:test')
const assert = require('node:assert/strict')

const { loadConfig, bindingBadge } = require('../lib/config')

describe('loadConfig', () => {
    test('defaults to loopback on port 3000', () => {
        assert.deepEqual(loadConfig({}), { host: '127.0.0.1', port: 3000 })
    })

    test('reads HOST and PORT from the environment', () => {
        assert.deepEqual(loadConfig({ HOST: ' 0.0.0.0 ', PORT: '8080' }), { host: '0.0.0.0', port: 8080 })
        assert.deepEqual(loadConfig({ PORT: '' }), { host: '127.0.0.1', port: 3000 })
    })

    test('rejects an invalid PORT', () => {
        assert.throws(() => loadConfig({ PORT: 'abc' }), /PORT must be an integer/)
        assert.throws(() => loadConfig({ PORT: '70000' }), /PORT must be an integer/)
        assert.throws(() => loadConfig({ PORT: '30.5' }), /PORT must be an integer/)
    })
})

describe('bindingBadge', () => {
    test('green for loopback', () => {
        for (const host of ['127.0.0.1', 'localhost', '::1']) {
            assert.equal(bindingBadge({ host, port: 3000 }).tone, 'local')
        }
        assert.deepEqual(bindingBadge({ host: '127.0.0.1', port: 3000 }), { tone: 'local', label: 'Local only', detail: '127.0.0.1:3000' })
    })

    test('red for all interfaces', () => {
        for (const host of ['0.0.0.0', '::', '']) {
            assert.equal(bindingBadge({ host, port: 3000 }).tone, 'exposed')
        }
        assert.equal(bindingBadge({ host: '', port: 1 }).detail, '0.0.0.0:1')
    })

    test('amber for a specific interface', () => {
        assert.deepEqual(bindingBadge({ host: '192.0.2.10', port: 3000 }), { tone: 'custom', label: 'Custom interface', detail: '192.0.2.10:3000' })
    })
})
