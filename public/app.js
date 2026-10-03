// Client-side niceties: confirm dialogs, copy buttons and JSON highlighting.
// Loaded as an external file because the Content-Security-Policy blocks inline script.
// Everything is built with textContent, never innerHTML.

document.addEventListener('submit', event => {
    const message = event.target.dataset.confirm
    if (message && !window.confirm(message)) event.preventDefault()
})

document.addEventListener('click', async event => {
    const button = event.target.closest('[data-copy]')
    if (!button) return
    const source = document.querySelector(button.dataset.copy)
    if (!source) return
    const label = button.textContent
    try {
        await navigator.clipboard.writeText(source.textContent)
        button.textContent = 'Copied'
    } catch {
        button.textContent = 'Copy failed'
    }
    setTimeout(() => { button.textContent = label }, 1500)
})

const JSON_TOKEN = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g

function highlightJson(pre) {
    const text = pre.textContent
    const fragment = document.createDocumentFragment()
    let last = 0
    for (const match of text.matchAll(JSON_TOKEN)) {
        if (match.index > last) fragment.append(text.slice(last, match.index))
        const span = document.createElement('span')
        if (match[1]) {
            span.className = match[2] ? 'j-key' : 'j-str'
            span.textContent = match[1]
            fragment.append(span)
            if (match[2]) fragment.append(match[2])
        } else {
            span.className = match[3] ? 'j-lit' : 'j-num'
            span.textContent = match[0]
            fragment.append(span)
        }
        last = match.index + match[0].length
    }
    fragment.append(text.slice(last))
    pre.replaceChildren(fragment)
}

document.querySelectorAll('pre[data-json]').forEach(highlightJson)
