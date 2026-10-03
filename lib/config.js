// Runtime configuration from environment variables.
//   HOST  interface to bind (default 127.0.0.1 - loopback only)
//   PORT  port to listen on (default 3000)

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1'])
const ALL_INTERFACES = new Set(['0.0.0.0', '::', ''])

function loadConfig(env = process.env) {
    const host = env.HOST === undefined ? '127.0.0.1' : env.HOST.trim()
    const port = env.PORT === undefined || env.PORT === '' ? 3000 : Number(env.PORT)
    if (!Number.isInteger(port) || port < 0 || port > 65535) {
        throw new Error(`PORT must be an integer between 0 and 65535, got "${env.PORT}".`)
    }
    return { host, port }
}

// Header badge describing who can reach the server:
// green = loopback only, amber = one specific interface, red = every interface.
function bindingBadge({ host, port }) {
    if (LOOPBACK.has(host)) return { tone: 'local', label: 'Local only', detail: `${host}:${port}` }
    if (ALL_INTERFACES.has(host)) return { tone: 'exposed', label: 'All interfaces', detail: `${host || '0.0.0.0'}:${port}` }
    return { tone: 'custom', label: 'Custom interface', detail: `${host}:${port}` }
}

module.exports = { loadConfig, bindingBadge }
