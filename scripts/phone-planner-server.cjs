const fs = require('fs')
const http = require('http')
const path = require('path')

const DEFAULT_HOST = '127.0.0.1'
const DEFAULT_PORT = 4176
const PHONE_PLANNER_STATIC_ROOT = path.resolve(__dirname, '..', 'src', 'phone-planner')
const CLOUDFLARE_SYNC_STATIC_ROOT = path.resolve(__dirname, '..', 'src', 'cloudflare-sync')
const CLOUDFLARE_SYNC_STATIC_FILES = new Set([
    'cloudflareCanonicalRequest.js',
    'cloudflareSyncConstants.js',
    'cloudflareSyncFetchClient.js'
])
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1'])

const MIME_TYPES = new Map([
    ['.html', 'text/html; charset=utf-8'],
    ['.js', 'text/javascript; charset=utf-8'],
    ['.css', 'text/css; charset=utf-8'],
    ['.json', 'application/json; charset=utf-8'],
    ['.webmanifest', 'application/manifest+json; charset=utf-8'],
    ['.svg', 'image/svg+xml'],
    ['.png', 'image/png'],
    ['.jpg', 'image/jpeg'],
    ['.jpeg', 'image/jpeg'],
    ['.ico', 'image/x-icon']
])

function isLoopbackHost(host) {
    return LOOPBACK_HOSTS.has(String(host || '').toLowerCase())
}

function parsePort(value) {
    if (value == null || value === '') return DEFAULT_PORT
    const port = Number(value)
    if (!Number.isSafeInteger(port) || port < 0 || port > 65535) {
        throw new Error('Phone planner port must be a number from 0 through 65535.')
    }
    return port
}

function parseArgs(argv = process.argv.slice(2), env = process.env) {
    let host = env.PHONE_PLANNER_HOST || DEFAULT_HOST
    let port = parsePort(env.PHONE_PLANNER_PORT)

    for (let index = 0; index < argv.length; index += 1) {
        const arg = argv[index]
        if (arg === '--host') {
            host = argv[index + 1] || ''
            index += 1
        } else if (arg.startsWith('--host=')) {
            host = arg.slice('--host='.length)
        } else if (arg === '--port') {
            port = parsePort(argv[index + 1])
            index += 1
        } else if (arg.startsWith('--port=')) {
            port = parsePort(arg.slice('--port='.length))
        } else if (arg === '--help' || arg === '-h') {
            return { help: true, host, port }
        } else {
            throw new Error(`Unsupported phone planner server option: ${arg}`)
        }
    }

    host = String(host || '').trim().toLowerCase()
    if (!isLoopbackHost(host)) {
        throw new Error('Phone planner server only binds to localhost, 127.0.0.1, or ::1.')
    }
    return { help: false, host, port }
}

function getContentType(filePath) {
    return MIME_TYPES.get(path.extname(filePath).toLowerCase()) || 'application/octet-stream'
}

function isWithinRoot(root, candidate) {
    const relative = path.relative(root, candidate)
    return relative === '' || !!relative && !relative.startsWith('..') && !path.isAbsolute(relative)
}

function safeDecodePathname(pathname) {
    try {
        return decodeURIComponent(pathname)
    } catch (_) {
        return null
    }
}

function getRawPathname(requestUrl) {
    const text = String(requestUrl || '/')
    if (text.startsWith('/')) {
        return text.split(/[?#]/, 1)[0] || '/'
    }

    const absoluteMatch = text.match(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i)
    if (absoluteMatch) {
        const rawPath = text.slice(absoluteMatch[0].length).split(/[?#]/, 1)[0]
        return rawPath || '/'
    }

    return null
}

function resolvePhonePlannerRequest(requestUrl, { staticRoot = PHONE_PLANNER_STATIC_ROOT } = {}) {
    const rawPathname = getRawPathname(requestUrl)
    if (!rawPathname || !rawPathname.startsWith('/')) {
        return { ok: false, statusCode: 400, reason: 'invalid-url' }
    }

    const decodedPathname = safeDecodePathname(rawPathname)
    if (!decodedPathname || decodedPathname.includes('\0') || decodedPathname.includes('\\')) {
        return { ok: false, statusCode: 403, reason: 'unsafe-path' }
    }

    const segments = decodedPathname.split('/').filter(Boolean)
    if (segments.some(segment => segment === '..' || segment === '.')) {
        return { ok: false, statusCode: 403, reason: 'path-traversal' }
    }

    const cloudflareSyncRequest = segments[0] === 'cloudflare-sync'
    const pathname = decodedPathname === '/' || decodedPathname.endsWith('/')
        ? `${decodedPathname}index.html`
        : decodedPathname
    const root = cloudflareSyncRequest ? CLOUDFLARE_SYNC_STATIC_ROOT : path.resolve(staticRoot)
    const relativePathname = cloudflareSyncRequest
        ? `/${segments.slice(1).join('/')}`
        : pathname
    if (cloudflareSyncRequest && (!segments[1] || segments.length !== 2 || !CLOUDFLARE_SYNC_STATIC_FILES.has(segments[1]))) {
        return { ok: false, statusCode: 404, reason: 'not-found' }
    }
    const filePath = path.resolve(root, `.${relativePathname}`)
    if (!isWithinRoot(root, filePath)) {
        return { ok: false, statusCode: 403, reason: 'outside-static-root' }
    }

    return {
        ok: true,
        statusCode: 200,
        filePath,
        contentType: getContentType(filePath)
    }
}

function createRequestHandler({ staticRoot = PHONE_PLANNER_STATIC_ROOT } = {}) {
    return async (req, res) => {
        if (!['GET', 'HEAD'].includes(req.method)) {
            res.writeHead(405, {
                'Allow': 'GET, HEAD',
                'Content-Type': 'text/plain; charset=utf-8'
            })
            res.end('Method not allowed')
            return
        }

        const resolved = resolvePhonePlannerRequest(req.url, { staticRoot })
        if (!resolved.ok) {
            res.writeHead(resolved.statusCode, {
                'Content-Type': 'text/plain; charset=utf-8',
                'X-Content-Type-Options': 'nosniff'
            })
            res.end(resolved.statusCode === 403 ? 'Forbidden' : 'Bad request')
            return
        }

        let stat
        try {
            stat = await fs.promises.stat(resolved.filePath)
        } catch (_) {
            res.writeHead(404, {
                'Content-Type': 'text/plain; charset=utf-8',
                'X-Content-Type-Options': 'nosniff'
            })
            res.end('Not found')
            return
        }

        if (!stat.isFile()) {
            res.writeHead(404, {
                'Content-Type': 'text/plain; charset=utf-8',
                'X-Content-Type-Options': 'nosniff'
            })
            res.end('Not found')
            return
        }

        res.writeHead(200, {
            'Content-Type': resolved.contentType,
            'Content-Length': stat.size,
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff'
        })
        if (req.method === 'HEAD') {
            res.end()
            return
        }
        fs.createReadStream(resolved.filePath).pipe(res)
    }
}

function startPhonePlannerServer({
    host = DEFAULT_HOST,
    port = DEFAULT_PORT,
    staticRoot = PHONE_PLANNER_STATIC_ROOT
} = {}) {
    if (!isLoopbackHost(host)) {
        throw new Error('Phone planner server only binds to loopback hosts.')
    }
    const server = http.createServer(createRequestHandler({ staticRoot }))
    return new Promise((resolve, reject) => {
        const onError = error => {
            server.off('listening', onListening)
            reject(error)
        }
        const onListening = () => {
            server.off('error', onError)
            const address = server.address()
            const actualPort = typeof address === 'object' && address ? address.port : port
            const displayHost = host === '::1' ? '[::1]' : host
            resolve({
                server,
                host,
                port: actualPort,
                url: `http://${displayHost}:${actualPort}/`,
                staticRoot: path.resolve(staticRoot)
            })
        }
        server.once('error', onError)
        server.once('listening', onListening)
        server.listen(port, host)
    })
}

function printHelp() {
    console.log('Usage: npm run phone-planner -- [--host 127.0.0.1] [--port 4176]')
    console.log('Serves only src/phone-planner on a loopback address.')
}

async function main() {
    const options = parseArgs()
    if (options.help) {
        printHelp()
        return
    }

    const started = await startPhonePlannerServer(options)
    console.log(`Wipesnap Phone Planner: ${started.url}`)
    console.log(`Serving static files from: ${started.staticRoot}`)
    console.log('Press Ctrl+C to stop.')
}

if (require.main === module) {
    main().catch(error => {
        console.error(error.message || error)
        process.exitCode = 1
    })
}

module.exports = {
    DEFAULT_HOST,
    DEFAULT_PORT,
    CLOUDFLARE_SYNC_STATIC_FILES,
    CLOUDFLARE_SYNC_STATIC_ROOT,
    PHONE_PLANNER_STATIC_ROOT,
    createRequestHandler,
    getContentType,
    isLoopbackHost,
    parseArgs,
    resolvePhonePlannerRequest,
    startPhonePlannerServer
}
