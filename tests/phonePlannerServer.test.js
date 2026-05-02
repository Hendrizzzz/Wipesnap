import assert from 'assert/strict'
import fs from 'fs'
import http from 'http'
import { createRequire } from 'module'
import { test } from 'node:test'
import os from 'os'
import path from 'path'

const require = createRequire(import.meta.url)
const firebaseJson = require('../firebase.json')
const packageJson = require('../package.json')
const {
    CLOUDFLARE_SYNC_STAGING_FILES,
    FORBIDDEN_ARTIFACT_NAMES,
    FORBIDDEN_ARTIFACT_SEGMENTS,
    OPTIONAL_STAGING_CONFIGS,
    PHONE_PLANNER_STAGING_FILES,
    assertSafeArtifactFiles,
    buildPhonePlannerStaging,
    copyOptionalStagingConfigs,
    targetDir
} = require('../scripts/build-phone-planner-staging.cjs')
const {
    CLOUDFLARE_SYNC_STATIC_ROOT,
    PHONE_PLANNER_STATIC_ROOT,
    parseArgs,
    resolvePhonePlannerRequest,
    startPhonePlannerServer
} = require('../scripts/phone-planner-server.cjs')

function request(url, { method = 'GET' } = {}) {
    return new Promise((resolve, reject) => {
        const req = http.request(url, { method }, res => {
            const chunks = []
            res.on('data', chunk => chunks.push(chunk))
            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    body: Buffer.concat(chunks).toString('utf8')
                })
            })
        })
        req.on('error', reject)
        req.end()
    })
}

async function closeServer(server) {
    await new Promise((resolve, reject) => {
        server.close(error => error ? reject(error) : resolve())
    })
}

test('phone planner server defaults to loopback and rejects non-loopback binds', () => {
    assert.equal(packageJson.scripts['phone-planner'], 'node scripts/phone-planner-server.cjs')
    assert.deepEqual(parseArgs([], {}), {
        help: false,
        host: '127.0.0.1',
        port: 4176
    })
    assert.deepEqual(parseArgs(['--port', '0'], {}), {
        help: false,
        host: '127.0.0.1',
        port: 0
    })
    assert.throws(() => parseArgs(['--host', '0.0.0.0'], {}), /only binds/)
    assert.throws(() => parseArgs(['--host', '192.168.1.5'], {}), /only binds/)
})

test('phone planner static resolver confines requests to src/phone-planner', () => {
    const index = resolvePhonePlannerRequest('/')
    const app = resolvePhonePlannerRequest('/app.js')
    const cloudflareFetchClient = resolvePhonePlannerRequest('/cloudflare-sync/cloudflareSyncFetchClient.js')
    const cloudflareForbidden = resolvePhonePlannerRequest('/cloudflare-sync/cloudflareD1Store.js')
    const traversal = resolvePhonePlannerRequest('/..%2Fpackage.json')
    const encodedTraversal = resolvePhonePlannerRequest('/%2e%2e/vault.json')
    const backslashTraversal = resolvePhonePlannerRequest('/..%5Cpackage.json')

    assert.equal(index.ok, true)
    assert.equal(path.resolve(index.filePath), path.join(PHONE_PLANNER_STATIC_ROOT, 'index.html'))
    assert.equal(app.ok, true)
    assert.equal(path.resolve(app.filePath), path.join(PHONE_PLANNER_STATIC_ROOT, 'app.js'))
    assert.equal(cloudflareFetchClient.ok, true)
    assert.equal(path.resolve(cloudflareFetchClient.filePath), path.join(CLOUDFLARE_SYNC_STATIC_ROOT, 'cloudflareSyncFetchClient.js'))
    assert.equal(cloudflareForbidden.ok, false)
    assert.equal(cloudflareForbidden.statusCode, 404)
    assert.equal(traversal.ok, false)
    assert.equal(traversal.statusCode, 403)
    assert.equal(encodedTraversal.ok, false)
    assert.equal(encodedTraversal.statusCode, 403)
    assert.equal(backslashTraversal.ok, false)
    assert.equal(backslashTraversal.statusCode, 403)
})

test('phone planner static server serves planner files and not repo root files', async () => {
    const started = await startPhonePlannerServer({ port: 0 })
    try {
        const index = await request(started.url)
        const app = await request(new URL('/app.js', started.url))
        const missingVault = await request(new URL('/vault.json', started.url))
        const packageTraversal = await request(new URL('/..%2Fpackage.json', started.url))
        const packageAtRoot = await request(new URL('/package.json', started.url))

        assert.equal(index.statusCode, 200)
        assert.match(index.body, /<div id="app"><\/div>/)
        assert.match(index.body, /type="module" src="\.\/app\.js"/)
        assert.equal(app.statusCode, 200)
        assert.match(app.body, /Local Draft Planner/)
        assert.equal(missingVault.statusCode, 404)
        assert.equal(packageTraversal.statusCode, 403)
        assert.equal(packageAtRoot.statusCode, 404)
    } finally {
        await closeServer(started.server)
    }
})

test('Firebase Hosting serves only the staged phone planner artifact with narrow CSP', () => {
    assert.equal(firebaseJson.hosting.target, 'phone-planner-staging')
    assert.equal(firebaseJson.hosting.public, 'out/phone-planner-staging')
    assert.notEqual(firebaseJson.hosting.public, '.')
    assert.notEqual(firebaseJson.hosting.public, 'src')

    const csp = firebaseJson.hosting.headers[0].headers
        .find(header => header.key === 'Content-Security-Policy')
        ?.value || ''
    assert.match(csp, /connect-src 'self'/)
    assert.doesNotMatch(csp, /connect-src\s+\*/)
    assert.doesNotMatch(csp, /localhost|127\.0\.0\.1/)
    assert.match(csp, /identitytoolkit\.googleapis\.com/)
    assert.match(csp, /firestore\.googleapis\.com/)
    assert.match(csp, /cloudfunctions\.net/)
    assert.match(csp, /workers\.dev/)

    for (const fileName of PHONE_PLANNER_STAGING_FILES) {
        assert.equal(path.dirname(fileName), '.')
        assert.equal(FORBIDDEN_ARTIFACT_NAMES.has(fileName), false)
        assert.equal(FORBIDDEN_ARTIFACT_SEGMENTS.has(fileName), false)
    }
    assert.equal(PHONE_PLANNER_STAGING_FILES.includes('app.js'), true)
    assert.equal(PHONE_PLANNER_STAGING_FILES.includes('phonePlannerCloudWorkflow.js'), true)
    assert.equal(PHONE_PLANNER_STAGING_FILES.includes('phonePlannerCloudflareRest.js'), true)
    assert.equal(CLOUDFLARE_SYNC_STAGING_FILES.includes('cloudflareSyncFetchClient.js'), true)
    assert.equal(PHONE_PLANNER_STAGING_FILES.includes('firebase-staging-config.example.json'), true)
    assert.equal(PHONE_PLANNER_STAGING_FILES.includes('cloudflare-sync-config.example.json'), true)

    buildPhonePlannerStaging()
    assertSafeArtifactFiles()
    const artifactFiles = new Set(fs.readdirSync(targetDir))
    assert.equal(artifactFiles.has('index.html'), true)
    assert.equal(artifactFiles.has('app.js'), true)
    assert.equal(artifactFiles.has('cloudflare-sync'), true)
    assert.equal(fs.existsSync(path.join(targetDir, 'cloudflare-sync', 'cloudflareSyncFetchClient.js')), true)
    assert.equal(artifactFiles.has('functions'), false)
    assert.equal(artifactFiles.has('tests'), false)
    assert.equal(artifactFiles.has('vault.json'), false)
    assert.equal(artifactFiles.has('package.json'), false)
})

test('hosted artifact optional staging configs are copied only when explicitly present', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'wipesnap-phone-config-copy-'))
    try {
        const sourceRoot = path.join(tempRoot, 'source')
        const targetRoot = path.join(tempRoot, 'target')
        fs.mkdirSync(sourceRoot)
        fs.mkdirSync(targetRoot)
        const warnings = []

        let copied = copyOptionalStagingConfigs({
            sourceRoot,
            targetRoot,
            warn: message => warnings.push(message)
        })
        assert.deepEqual(copied, [])
        assert.equal(warnings.length, OPTIONAL_STAGING_CONFIGS.length)
        assert.equal(fs.existsSync(path.join(targetRoot, 'cloudflare-sync-config.json')), false)

        fs.writeFileSync(path.join(sourceRoot, 'cloudflare-sync-config.json'), JSON.stringify({
            environment: 'staging',
            provider: 'cloudflare',
            apiBaseUrl: 'https://example-stage.workers.dev',
            useLocalDev: false
        }))
        warnings.length = 0
        copied = copyOptionalStagingConfigs({
            sourceRoot,
            targetRoot,
            warn: message => warnings.push(message)
        })
        assert.deepEqual(copied, ['cloudflare-sync-config.json'])
        assert.equal(warnings.length, 1)
        assert.equal(fs.existsSync(path.join(targetRoot, 'cloudflare-sync-config.json')), true)
        assert.equal(fs.existsSync(path.join(targetRoot, 'vault.json')), false)
        assert.equal(fs.existsSync(path.join(targetRoot, 'package.json')), false)
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true })
    }
})
