import {
    CLOUD_SYNC_PATCH_DOC_TYPE,
    CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
    validateCloudSyncDeviceRecordForPhone,
    validateCloudSyncEnvelopeForPhone,
    validateCloudSyncKeyGrantForPhone
} from '../phone-planner/phonePlannerCloudCrypto.js'
import {
    CLOUDFLARE_SYNC_LIMITS,
    CLOUDFLARE_SYNC_OPERATIONS
} from './cloudflareSyncConstants.js'
import {
    cloudflareRequestAuthFromHeaders,
    createCloudflareCanonicalRequestMetadata,
    sha256Base64Url,
    verifyCloudflareCanonicalRequest
} from './cloudflareCanonicalRequest.js'

const SAFE_ID = /^[A-Za-z][A-Za-z0-9_-]{1,120}$/
const OWNER_UID = /^[A-Za-z0-9:_-]{1,128}$/
const SAFE_STATUS = /^(?:pending|approved|claimed|active|revoked|accepted|applied|conflict|skipped)$/
const FORBIDDEN_BACKEND_TEXT = /deviceSessionToken|customToken|bearer\s+|syncRootKey|rootKeyMaterial|privateKey|vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile|AppData[\\/]|cap_[A-Za-z0-9_-]{4,128}|[A-Za-z]:[\\/]|\\\\|HKEY_|HKLM|HKCU|powershell|taskkill|cmd\s|launchAuthority|vaultData|browserSession|credential|password|cookie|oauth|refreshToken|accessToken|idToken/i
const BACKEND_OPAQUE_KEYS = new Set([
    'ciphertext',
    'ciphertextHash',
    'fingerprint',
    'iv',
    'salt',
    'spki',
    'tag',
    'value',
    'wrappedKeyCiphertext',
    'wrappedKeyHash',
    'signature'
])
const RATE_LIMITED_OPERATIONS = new Map([
    [CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop, {
        action: 'bootstrap-desktop',
        max: CLOUDFLARE_SYNC_LIMITS.maxBootstrapRequestsPerWindow
    }],
    [CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment, {
        action: 'request-enrollment',
        max: CLOUDFLARE_SYNC_LIMITS.maxEnrollmentRequestsPerWindow
    }]
])

export class CloudflareSyncError extends Error {
    constructor(status, code, message) {
        super(message)
        this.name = 'CloudflareSyncError'
        this.status = status
        this.code = code
    }
}

function fail(status, code, message) {
    throw new CloudflareSyncError(status, code, message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function jsonBytes(value) {
    return new TextEncoder().encode(typeof value === 'string' ? value : JSON.stringify(value ?? null)).length
}

function headerValue(headers, name) {
    if (!headers) return ''
    return typeof headers.get === 'function' ? headers.get(name) || '' : ''
}

async function requestIpHash(request, cryptoApi) {
    const raw = (
        headerValue(request.headers, 'cf-connecting-ip') ||
        headerValue(request.headers, 'x-forwarded-for').split(',')[0] ||
        'unknown'
    ).trim().slice(0, 128) || 'unknown'
    return sha256Base64Url(raw, cryptoApi)
}

function requireObject(value, fieldName) {
    if (!isPlainObject(value)) fail(400, 'invalid-argument', `${fieldName} must be an object.`)
    return value
}

function safeString(value, fieldName, pattern = SAFE_ID, max = 128) {
    if (typeof value !== 'string') fail(400, 'invalid-argument', `${fieldName} must be a string.`)
    const text = value.trim()
    if (!text || text.length > max || !pattern.test(text)) fail(400, 'invalid-argument', `${fieldName} is not safe.`)
    return text
}

function safeInteger(value, fieldName, { positive = false } = {}) {
    if (!Number.isSafeInteger(value) || value < (positive ? 1 : 0)) {
        fail(400, 'invalid-argument', `${fieldName} must be a safe integer.`)
    }
    return value
}

function assertNoForbiddenBackendMaterial(value, path = 'cloudflare sync document') {
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoForbiddenBackendMaterial(item, `${path}[${index}]`))
        return
    }
    if (isPlainObject(value)) {
        for (const [key, nested] of Object.entries(value)) {
            if (BACKEND_OPAQUE_KEYS.has(key)) continue
            const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '')
            if (/(payload|plaintext|vault|capability|launch|path|registry|process|command|token|credential|password|privatekey|syncrootkey|session)/.test(normalized)) {
                fail(400, 'forbidden-material', `${path}.${key} is not allowed in backend-visible Cloudflare sync data.`)
            }
            assertNoForbiddenBackendMaterial(nested, `${path}.${key}`)
        }
        return
    }
    if (typeof value === 'string' && FORBIDDEN_BACKEND_TEXT.test(value)) {
        fail(400, 'forbidden-material', `${path} contains forbidden backend-visible material.`)
    }
}

function validateEnvelope(input, expectedDocType) {
    assertNoForbiddenBackendMaterial(input)
    let envelope
    try {
        envelope = validateCloudSyncEnvelopeForPhone(input, { expectedDocType })
    } catch (error) {
        fail(400, 'invalid-envelope', error?.message || 'Encrypted cloud sync envelope is invalid.')
    }
    if (jsonBytes(envelope) > CLOUDFLARE_SYNC_LIMITS.maxEnvelopeJsonBytes) {
        fail(413, 'too-large', 'Encrypted cloud sync envelope is too large.')
    }
    return envelope
}

function validateKeyGrant(input) {
    assertNoForbiddenBackendMaterial(input)
    try {
        return validateCloudSyncKeyGrantForPhone(input)
    } catch (error) {
        fail(400, 'invalid-key-grant', error?.message || 'Cloud sync key grant is invalid.')
    }
}

function validateDevice(input, expectedStatus = null) {
    assertNoForbiddenBackendMaterial(input)
    let device
    try {
        device = validateCloudSyncDeviceRecordForPhone(input)
    } catch (error) {
        fail(400, 'invalid-device', error?.message || 'Cloud sync device record is invalid.')
    }
    if (expectedStatus && device.status !== expectedStatus) {
        fail(400, 'invalid-device', `Device must be ${expectedStatus}.`)
    }
    return device
}

function validateDecision(input = {}) {
    const decision = requireObject(input, 'patch decision')
    assertNoForbiddenBackendMaterial(decision)
    const status = safeString(decision.status, 'decision.status', /^(?:applied|conflict|skipped)$/, 40)
    const reason = safeString(decision.reason, 'decision.reason', /^[a-z][a-z0-9-]{1,80}$/, 80)
    return {
        product: 'wipesnap',
        schemaVersion: 1,
        metadataOnly: true,
        ownerUid: safeString(decision.ownerUid, 'decision.ownerUid', OWNER_UID, 128),
        patchRevisionId: safeString(decision.patchRevisionId, 'decision.patchRevisionId', /^patchrev_[A-Za-z0-9_-]{1,85}$/, 96),
        sourcePatchDeviceId: safeString(decision.sourcePatchDeviceId, 'decision.sourcePatchDeviceId', /^dev_[A-Za-z0-9_-]{1,92}$/, 96),
        desktopDeviceId: safeString(decision.desktopDeviceId, 'decision.desktopDeviceId', /^dev_[A-Za-z0-9_-]{1,92}$/, 96),
        status,
        reason,
        decidedAt: safeInteger(decision.decidedAt, 'decision.decidedAt')
    }
}

function routeFor(request) {
    const url = new URL(request.url)
    const method = request.method.toUpperCase()
    const fixed = {
        'POST /v1/bootstrap/desktop': CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop,
        'POST /v1/enrollments/request': CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment,
        'GET /v1/enrollments/pending': CLOUDFLARE_SYNC_OPERATIONS.listPendingEnrollments,
        'POST /v1/enrollments/approve': CLOUDFLARE_SYNC_OPERATIONS.approveEnrollment,
        'POST /v1/enrollments/claim': CLOUDFLARE_SYNC_OPERATIONS.claimEnrollment,
        'POST /v1/snapshots': CLOUDFLARE_SYNC_OPERATIONS.uploadSnapshot,
        'GET /v1/snapshots/latest': CLOUDFLARE_SYNC_OPERATIONS.getLatestSnapshot,
        'POST /v1/patches': CLOUDFLARE_SYNC_OPERATIONS.uploadPatch,
        'GET /v1/patches': CLOUDFLARE_SYNC_OPERATIONS.listPendingPatches
    }[`${method} ${url.pathname}`]
    if (fixed) return { operation: fixed, path: url.pathname }
    if (method === 'GET' && /^\/v1\/snapshots\/[^/]+$/.test(url.pathname)) {
        return { operation: CLOUDFLARE_SYNC_OPERATIONS.getSnapshot, path: url.pathname }
    }
    if (method === 'GET' && /^\/v1\/patches\/[^/]+$/.test(url.pathname)) {
        return { operation: CLOUDFLARE_SYNC_OPERATIONS.getPatch, path: url.pathname }
    }
    if (method === 'GET' && /^\/v1\/devices\/[^/]+$/.test(url.pathname)) {
        return { operation: CLOUDFLARE_SYNC_OPERATIONS.getDevice, path: url.pathname }
    }
    if (method === 'POST' && /^\/v1\/patches\/[^/]+\/decision$/.test(url.pathname)) {
        return { operation: CLOUDFLARE_SYNC_OPERATIONS.recordPatchDecision, path: url.pathname }
    }
    if (method === 'POST' && /^\/v1\/devices\/[^/]+\/revoke$/.test(url.pathname)) {
        return { operation: CLOUDFLARE_SYNC_OPERATIONS.revokeDevice, path: url.pathname }
    }
    return null
}

function responseJson(body, status = 200) {
    return new Response(JSON.stringify({ ...body, metadataOnly: true }), {
        status,
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store'
        }
    })
}

async function readBody(request) {
    const text = await request.text()
    if (jsonBytes(text) > CLOUDFLARE_SYNC_LIMITS.maxRequestJsonBytes) {
        fail(413, 'too-large', 'Cloudflare sync request body is too large.')
    }
    if (!text) return { text: '', json: {} }
    try {
        return { text, json: JSON.parse(text) }
    } catch (_) {
        fail(400, 'invalid-json', 'Cloudflare sync request body must be JSON.')
    }
}

function assertRole(auth, allowed) {
    if (!allowed.includes(auth.deviceRole)) fail(403, 'wrong-role', 'Device role is not allowed for this operation.')
}

function assertDeviceIdentityMatchesAuth(device, auth) {
    if (device.ownerUid !== auth.ownerUid) fail(403, 'wrong-owner', 'Device owner does not match request.')
    if (device.deviceId !== auth.deviceId) fail(403, 'wrong-device', 'Device id does not match request.')
    if (device.role !== auth.deviceRole) fail(403, 'wrong-role', 'Device role does not match request.')
    if (device.enrollmentEpoch !== auth.enrollmentEpoch) fail(403, 'stale-epoch', 'Device enrollment epoch is stale.')
    if (device.keyVersion !== auth.keyVersion) fail(403, 'stale-key-version', 'Device key version is stale.')
}

function assertDeviceMatchesAuth(device, auth) {
    assertDeviceIdentityMatchesAuth(device, auth)
    if (device.status !== 'active' || device.revokedAt != null) fail(403, 'revoked-device', 'Device is not active.')
}

function assertScope(device, scope) {
    if (!Array.isArray(device.syncScopes) || !device.syncScopes.includes(scope)) {
        fail(403, 'missing-scope', `Device lacks ${scope} scope.`)
    }
}

async function verifyRequest({ store, request, route, bodyText, bodyJson, now, cryptoApi }) {
    const ipHash = await requestIpHash(request, cryptoApi)
    let auth
    try {
        auth = cloudflareRequestAuthFromHeaders(request.headers)
    } catch (_) {
        await store.recordFailedSignature({
            ownerUid: 'unknown',
            deviceId: 'unknown',
            ipHash,
            bucketMs: Math.floor(now / CLOUDFLARE_SYNC_LIMITS.rateWindowMs) * CLOUDFLARE_SYNC_LIMITS.rateWindowMs,
            max: CLOUDFLARE_SYNC_LIMITS.maxFailedSignaturesPerWindow,
            now
        })
        fail(403, 'malformed-signature', 'Request authentication metadata is invalid.')
    }
    const computedHash = await sha256Base64Url(bodyText || '', cryptoApi)
    if (computedHash !== auth.bodyHash) fail(403, 'tampered-body', 'Request body hash does not match.')
    if (Math.abs(now - auth.requestedAt) > CLOUDFLARE_SYNC_LIMITS.maxClockSkewMs) {
        fail(403, 'stale-request', 'Request timestamp is outside the allowed window.')
    }
    const signatureDevice = route.operation === CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop ||
        route.operation === CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment
        ? validateDevice(bodyJson.document)
        : validateDevice(await store.getDevice(auth.ownerUid, auth.deviceId))
    if (signatureDevice.deviceId !== auth.signatureKeyId) fail(403, 'wrong-device', 'Signature key id does not match device.')
    if (route.operation === CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment && signatureDevice.status !== 'pending') {
        fail(400, 'invalid-device', 'Enrollment request device must be pending.')
    }
    if (route.operation === CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop && signatureDevice.role !== 'desktop') {
        fail(403, 'wrong-role', 'Bootstrap requires a desktop device.')
    }
    if (![CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop, CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment].includes(route.operation)) {
        assertDeviceMatchesAuth(signatureDevice, auth)
    } else {
        assertDeviceIdentityMatchesAuth(signatureDevice, auth)
    }
    const canonicalMetadata = createCloudflareCanonicalRequestMetadata({
        ...auth,
        method: request.method.toUpperCase(),
        path: new URL(request.url).pathname + new URL(request.url).search,
        operation: route.operation
    })
    let valid = false
    try {
        valid = await verifyCloudflareCanonicalRequest({
            canonicalMetadata,
            signature: auth.signature,
            publicKeyRecord: signatureDevice.signingPublicKey,
            cryptoApi
        })
    } catch (_) {
        await store.recordFailedSignature({
            ownerUid: auth.ownerUid,
            deviceId: auth.deviceId,
            ipHash,
            bucketMs: Math.floor(now / CLOUDFLARE_SYNC_LIMITS.rateWindowMs) * CLOUDFLARE_SYNC_LIMITS.rateWindowMs,
            max: CLOUDFLARE_SYNC_LIMITS.maxFailedSignaturesPerWindow,
            now
        })
        fail(403, 'malformed-signature', 'Request signature is not valid.')
    }
    if (!valid) {
        await store.recordFailedSignature({
            ownerUid: auth.ownerUid,
            deviceId: auth.deviceId,
            ipHash,
            bucketMs: Math.floor(now / CLOUDFLARE_SYNC_LIMITS.rateWindowMs) * CLOUDFLARE_SYNC_LIMITS.rateWindowMs,
            max: CLOUDFLARE_SYNC_LIMITS.maxFailedSignaturesPerWindow,
            now
        })
        fail(403, 'malformed-signature', 'Request signature is not valid.')
    }
    const bucketMs = Math.floor(now / CLOUDFLARE_SYNC_LIMITS.rateWindowMs) * CLOUDFLARE_SYNC_LIMITS.rateWindowMs
    const preEnrollmentRateLimit = RATE_LIMITED_OPERATIONS.get(route.operation)
    const sequenceAdvanced = !preEnrollmentRateLimit
    if (preEnrollmentRateLimit) {
        await store.recordRateLimit({
            ownerUid: auth.ownerUid,
            deviceId: auth.deviceId,
            ipHash,
            action: preEnrollmentRateLimit.action,
            bucketMs,
            max: preEnrollmentRateLimit.max,
            now
        })
    } else {
        await store.recordRateLimit({
            ownerUid: auth.ownerUid,
            deviceId: auth.deviceId,
            ipHash,
            action: 'signed-request',
            bucketMs,
            max: CLOUDFLARE_SYNC_LIMITS.maxSignedRequestsPerWindow,
            now
        })
        await store.advanceDeviceSequence({
            ownerUid: auth.ownerUid,
            deviceId: auth.deviceId,
            deviceSequence: auth.deviceSequence,
            operation: route.operation,
            documentId: bodyJson.documentId || bodyJson.requestId || bodyJson.revisionId || new URL(request.url).pathname,
            now
        })
    }
    return { auth, device: signatureDevice, sequenceAdvanced }
}

export function createCloudflareSyncWorkerCore({
    store,
    cryptoApi = globalThis.crypto,
    now = Date.now
} = {}) {
    if (!store) throw new Error('Cloudflare sync Worker core requires a D1-backed store.')
    const clock = () => (typeof now === 'function' ? now() : now)

    async function handle(request) {
        let verified = null
        try {
            const route = routeFor(request)
            if (!route) return responseJson({ error: 'not-found', status: 'not-found' }, 404)
            const currentTime = clock()
            const body = await readBody(request)
            verified = await verifyRequest({
                store,
                request,
                route,
                bodyText: body.text,
                bodyJson: body.json,
                now: currentTime,
                cryptoApi
            })
            const { auth, device } = verified
            const payload = await dispatch({
                store,
                operation: route.operation,
                auth,
                device,
                body: body.json,
                request,
                now: currentTime
            })
            return responseJson(payload)
        } catch (error) {
            const recoveredSequence = verified?.sequenceAdvanced === true
                ? { deviceSequence: verified.auth.deviceSequence }
                : {}
            if (error instanceof CloudflareSyncError) {
                return responseJson({ error: error.code, status: 'rejected', message: error.message, ...recoveredSequence }, error.status)
            }
            return responseJson({ error: 'rejected', status: 'rejected', message: 'Cloudflare sync request failed.', ...recoveredSequence }, 500)
        }
    }

    return { handle }
}

async function dispatch({ store, operation, auth, device, body, request, now }) {
    if (operation === CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop) {
        const desktop = validateDevice(body.document, 'active')
        if (desktop.role !== 'desktop') fail(403, 'wrong-role', 'Bootstrap requires desktop role.')
        await store.bootstrapDesktop({ ownerUid: desktop.ownerUid, device: desktop, now })
        return { status: 'accepted', ownerUid: desktop.ownerUid, deviceId: desktop.deviceId }
    }
    if (operation === CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment) {
        const pending = validateDevice(body.document, 'pending')
        if (pending.role === 'desktop') fail(403, 'wrong-role', 'Additional desktop enrollment is not supported.')
        const pairingChallengeHash = safeString(body.pairingChallengeHash, 'pairingChallengeHash', /^[A-Za-z0-9_-]{32,128}$/, 128)
        await store.requestEnrollment({ ownerUid: pending.ownerUid, requestId: pending.deviceId, device: pending, pairingChallengeHash, now })
        return { status: 'pending', requestId: pending.deviceId, deviceId: pending.deviceId }
    }
    if (operation === CLOUDFLARE_SYNC_OPERATIONS.listPendingEnrollments) {
        assertRole(auth, ['desktop'])
        assertScope(device, 'read')
        return { status: 'listed', records: await store.listPendingEnrollments(auth.ownerUid) }
    }
    if (operation === CLOUDFLARE_SYNC_OPERATIONS.approveEnrollment) {
        assertRole(auth, ['desktop'])
        const requestId = safeString(body.requestId, 'requestId', /^dev_[A-Za-z0-9_-]{1,92}$/, 96)
        const keyGrant = validateKeyGrant(body.keyGrant)
        if (keyGrant.ownerUid !== auth.ownerUid || keyGrant.createdByDeviceId !== auth.deviceId) {
            fail(403, 'wrong-owner', 'Key grant owner or creator does not match desktop.')
        }
        const approved = await store.approveEnrollment({ ownerUid: auth.ownerUid, requestId, desktopDeviceId: auth.deviceId, keyGrant, now })
        return { status: 'approved', requestId, deviceId: approved.device.deviceId, keyGrantId: keyGrant.grantId }
    }
    if (operation === CLOUDFLARE_SYNC_OPERATIONS.claimEnrollment) {
        assertRole(auth, ['phone', 'web-planner'])
        assertScope(device, 'read')
        assertScope(device, 'patch-upload')
        const requestId = safeString(body.requestId, 'requestId', /^dev_[A-Za-z0-9_-]{1,92}$/, 96)
        const keyGrantId = safeString(body.keyGrantId, 'keyGrantId', /^grant_[A-Za-z0-9_-]{1,90}$/, 96)
        const pairingChallengeHash = safeString(body.pairingChallengeHash, 'pairingChallengeHash', /^[A-Za-z0-9_-]{32,128}$/, 128)
        const claimed = await store.claimEnrollment({ ownerUid: auth.ownerUid, requestId, deviceId: auth.deviceId, keyGrantId, pairingChallengeHash, now })
        return { status: 'accepted', device: claimed.device, keyGrant: claimed.keyGrant }
    }
    if (operation === CLOUDFLARE_SYNC_OPERATIONS.uploadSnapshot) {
        assertRole(auth, ['desktop'])
        assertScope(device, 'snapshot-upload')
        const envelope = validateEnvelope(body.document, CLOUD_SYNC_SNAPSHOT_DOC_TYPE)
        if (envelope.ownerUid !== auth.ownerUid || envelope.deviceId !== auth.deviceId || envelope.deviceSequence !== auth.deviceSequence) {
            fail(403, 'wrong-device', 'Snapshot envelope does not match signer.')
        }
        await store.insertSnapshot({ ownerUid: auth.ownerUid, envelope, now })
        return { status: 'accepted', revisionId: envelope.revisionId }
    }
    if (operation === CLOUDFLARE_SYNC_OPERATIONS.getLatestSnapshot) {
        assertScope(device, 'read')
        return { status: 'downloaded', envelope: await store.getLatestSnapshot(auth.ownerUid) }
    }
    if (operation === CLOUDFLARE_SYNC_OPERATIONS.getSnapshot) {
        assertScope(device, 'read')
        const revisionId = safeString(new URL(request.url).pathname.split('/').pop(), 'revisionId', /^srev_[A-Za-z0-9_-]{1,90}$/, 96)
        return { status: 'downloaded', envelope: await store.getSnapshot(auth.ownerUid, revisionId) }
    }
    if (operation === CLOUDFLARE_SYNC_OPERATIONS.uploadPatch) {
        assertRole(auth, ['phone', 'web-planner'])
        assertScope(device, 'patch-upload')
        const envelope = validateEnvelope(body.document, CLOUD_SYNC_PATCH_DOC_TYPE)
        if (envelope.ownerUid !== auth.ownerUid || envelope.deviceId !== auth.deviceId || envelope.deviceSequence !== auth.deviceSequence) {
            fail(403, 'wrong-device', 'Patch envelope does not match signer.')
        }
        await store.insertPatch({ ownerUid: auth.ownerUid, envelope, now })
        return { status: 'accepted', patchRevisionId: envelope.revisionId }
    }
    if (operation === CLOUDFLARE_SYNC_OPERATIONS.listPendingPatches) {
        assertRole(auth, ['desktop'])
        assertScope(device, 'read')
        return { status: 'listed', records: await store.listPatches(auth.ownerUid, 'pending') }
    }
    if (operation === CLOUDFLARE_SYNC_OPERATIONS.getPatch) {
        assertRole(auth, ['desktop'])
        assertScope(device, 'read')
        const revisionId = safeString(new URL(request.url).pathname.split('/').pop(), 'patchRevisionId', /^patchrev_[A-Za-z0-9_-]{1,85}$/, 96)
        const patch = await store.getPatch(auth.ownerUid, revisionId, 'pending')
        return { status: patch ? 'downloaded' : 'not-found', envelope: patch?.envelope || null, patchStatus: patch?.status || 'not-found' }
    }
    if (operation === CLOUDFLARE_SYNC_OPERATIONS.getDevice) {
        assertScope(device, 'read')
        const targetDeviceId = safeString(new URL(request.url).pathname.split('/').pop(), 'targetDeviceId', /^dev_[A-Za-z0-9_-]{1,92}$/, 96)
        return { status: 'downloaded', device: await store.getDevice(auth.ownerUid, targetDeviceId) }
    }
    if (operation === CLOUDFLARE_SYNC_OPERATIONS.recordPatchDecision) {
        assertRole(auth, ['desktop'])
        const decision = validateDecision(body.decision)
        if (decision.ownerUid !== auth.ownerUid || decision.desktopDeviceId !== auth.deviceId) {
            fail(403, 'wrong-owner', 'Patch decision does not match desktop.')
        }
        await store.recordPatchDecision({ ownerUid: auth.ownerUid, decision, now })
        return { status: decision.status, reason: decision.reason, patchRevisionId: decision.patchRevisionId }
    }
    if (operation === CLOUDFLARE_SYNC_OPERATIONS.revokeDevice) {
        assertRole(auth, ['desktop'])
        const targetDeviceId = safeString(new URL(request.url).pathname.split('/').at(-2), 'targetDeviceId', /^dev_[A-Za-z0-9_-]{1,92}$/, 96)
        await store.revokeDevice({ ownerUid: auth.ownerUid, targetDeviceId, revokedByDeviceId: auth.deviceId, now })
        return { status: 'revoked', deviceId: targetDeviceId, cachedClientDataMayRemain: true }
    }
    fail(404, 'not-found', 'Cloudflare sync operation is not implemented.')
}

export function cloudflareSyncBackendContainsForbiddenMaterial(value) {
    try {
        assertNoForbiddenBackendMaterial(value)
        return false
    } catch (_) {
        return true
    }
}
