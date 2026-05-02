import {
    CLOUDFLARE_SYNC_OPERATIONS,
    CLOUDFLARE_SYNC_SIGNING_HEADERS
} from './cloudflareSyncConstants.js'
import {
    createCloudflareCanonicalRequestMetadata,
    sha256Base64Url
} from './cloudflareCanonicalRequest.js'

const HTTPS_BASE_URL = /^https:\/\/[A-Za-z0-9.-]+(?::\d{1,5})?(?:\/[A-Za-z0-9._~!$&'()*+,;=:@%-]*)?$/
const LOCAL_BASE_URL = /^http:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):\d{1,5}(?:\/[A-Za-z0-9._~!$&'()*+,;=:@%-]*)?$/
const OWNER_UID = /^[A-Za-z0-9:_-]{1,128}$/
const DEVICE_ID = /^dev_[A-Za-z0-9_-]{1,92}$/
const REVISION_ID = /^(?:srev|patchrev)_[A-Za-z0-9_-]{1,90}$/

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function safeString(value, fieldName, pattern, max = 160) {
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    const text = value.trim()
    if (!text || text.length > max || (pattern && !pattern.test(text))) {
        fail(`${fieldName} is not safe.`)
    }
    return text
}

function safeInteger(value, fieldName) {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${fieldName} must be a non-negative safe integer.`)
    return value
}

function normalizeBaseUrl(value, { useLocalDev = false } = {}) {
    const text = safeString(value, 'Cloudflare sync apiBaseUrl', useLocalDev ? LOCAL_BASE_URL : HTTPS_BASE_URL, 240)
        .replace(/\/+$/g, '')
    if (!useLocalDev && /(?:^|[.-])prod(?:uction)?(?:[.-]|$)|wipesnap\.com/i.test(text)) {
        fail('Cloudflare sync refuses production-looking API URLs during staging integration.')
    }
    return text
}

function normalizeDeviceState(input = {}) {
    const state = typeof input === 'function' ? input() : input
    if (!isPlainObject(state)) fail('Cloudflare sync request requires device state.')
    const device = state.device
    if (!isPlainObject(device)) fail('Cloudflare sync request requires a device record.')
    return {
        ownerUid: safeString(state.ownerUid || device.ownerUid, 'ownerUid', OWNER_UID, 128),
        device,
        signingPrivateKey: state.signingPrivateKey
    }
}

function methodAndBody(method, body) {
    const normalizedMethod = safeString(method, 'method', /^(?:GET|POST)$/, 8).toUpperCase()
    const bodyText = normalizedMethod === 'GET' ? '' : JSON.stringify(body ?? {})
    return { method: normalizedMethod, bodyText }
}

function sanitizedCloudflareError(response, json) {
    const code = typeof json?.error === 'string' ? json.error : `http-${response.status}`
    const error = new Error('Cloudflare staging sync request failed.')
    error.code = code
    error.status = response.status
    if (Number.isSafeInteger(json?.deviceSequence) && json.deviceSequence >= 0) {
        error.deviceSequence = json.deviceSequence
    }
    error.metadataOnly = true
    return error
}

function operationPath(operation, params = {}) {
    switch (operation) {
        case CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop:
            return '/v1/bootstrap/desktop'
        case CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment:
            return '/v1/enrollments/request'
        case CLOUDFLARE_SYNC_OPERATIONS.listPendingEnrollments:
            return '/v1/enrollments/pending'
        case CLOUDFLARE_SYNC_OPERATIONS.approveEnrollment:
            return '/v1/enrollments/approve'
        case CLOUDFLARE_SYNC_OPERATIONS.claimEnrollment:
            return '/v1/enrollments/claim'
        case CLOUDFLARE_SYNC_OPERATIONS.uploadSnapshot:
            return '/v1/snapshots'
        case CLOUDFLARE_SYNC_OPERATIONS.getLatestSnapshot:
            return '/v1/snapshots/latest'
        case CLOUDFLARE_SYNC_OPERATIONS.getSnapshot:
            return `/v1/snapshots/${encodeURIComponent(safeString(params.revisionId, 'revisionId', REVISION_ID, 96))}`
        case CLOUDFLARE_SYNC_OPERATIONS.uploadPatch:
            return '/v1/patches'
        case CLOUDFLARE_SYNC_OPERATIONS.listPendingPatches:
            return '/v1/patches?status=pending'
        case CLOUDFLARE_SYNC_OPERATIONS.getPatch:
            return `/v1/patches/${encodeURIComponent(safeString(params.revisionId, 'patchRevisionId', REVISION_ID, 96))}`
        case CLOUDFLARE_SYNC_OPERATIONS.getDevice:
            return `/v1/devices/${encodeURIComponent(safeString(params.deviceId, 'deviceId', DEVICE_ID, 96))}`
        case CLOUDFLARE_SYNC_OPERATIONS.recordPatchDecision:
            return `/v1/patches/${encodeURIComponent(safeString(params.revisionId, 'patchRevisionId', REVISION_ID, 96))}/decision`
        case CLOUDFLARE_SYNC_OPERATIONS.revokeDevice:
            return `/v1/devices/${encodeURIComponent(safeString(params.deviceId, 'deviceId', DEVICE_ID, 96))}/revoke`
        default:
            fail('Cloudflare sync operation is not supported by the fetch client.')
    }
}

export function createCloudflareSyncFetchClient({
    apiBaseUrl,
    useLocalDev = false,
    fetchImpl = globalThis.fetch?.bind(globalThis),
    cryptoApi = globalThis.crypto,
    now = Date.now,
    signCanonicalMetadata = null
} = {}) {
    const baseUrl = normalizeBaseUrl(apiBaseUrl, { useLocalDev })
    if (typeof fetchImpl !== 'function') fail('Cloudflare sync fetch client requires fetch.')
    if (!cryptoApi?.subtle) fail('Cloudflare sync fetch client requires WebCrypto SHA-256.')
    const clock = () => (typeof now === 'function' ? now() : now)
    const sign = signCanonicalMetadata || (() => fail('Cloudflare sync fetch client requires a request signing callback.'))

    async function signedFetch({
        method = 'GET',
        path,
        operation,
        body,
        deviceState,
        deviceSequence
    } = {}) {
        const state = normalizeDeviceState(deviceState)
        const device = state.device
        const sequence = safeInteger(deviceSequence, 'deviceSequence')
        const { method: normalizedMethod, bodyText } = methodAndBody(method, body)
        const requestedAt = clock()
        const auth = {
            ownerUid: state.ownerUid,
            deviceId: safeString(device.deviceId, 'device.deviceId', DEVICE_ID, 96),
            deviceRole: safeString(device.role, 'device.role', /^(?:desktop|phone|web-planner)$/, 40),
            enrollmentEpoch: safeInteger(device.enrollmentEpoch, 'device.enrollmentEpoch'),
            keyVersion: safeInteger(device.keyVersion, 'device.keyVersion'),
            deviceSequence: sequence,
            requestedAt,
            bodyHash: await sha256Base64Url(bodyText, cryptoApi),
            signatureAlg: 'ECDSA-P256-SHA256-P1363',
            signatureKeyId: device.deviceId,
            signature: ''
        }
        auth.signature = await sign({
            canonicalMetadata: createCloudflareCanonicalRequestMetadata({
                ...auth,
                method: normalizedMethod,
                path,
                operation
            }),
            privateKey: state.signingPrivateKey,
            device: clone(device),
            auth: clone(auth)
        })
        const response = await fetchImpl(`${baseUrl}${path}`, {
            method: normalizedMethod,
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
                [CLOUDFLARE_SYNC_SIGNING_HEADERS.ownerUid]: auth.ownerUid,
                [CLOUDFLARE_SYNC_SIGNING_HEADERS.deviceId]: auth.deviceId,
                [CLOUDFLARE_SYNC_SIGNING_HEADERS.deviceRole]: auth.deviceRole,
                [CLOUDFLARE_SYNC_SIGNING_HEADERS.enrollmentEpoch]: String(auth.enrollmentEpoch),
                [CLOUDFLARE_SYNC_SIGNING_HEADERS.keyVersion]: String(auth.keyVersion),
                [CLOUDFLARE_SYNC_SIGNING_HEADERS.deviceSequence]: String(auth.deviceSequence),
                [CLOUDFLARE_SYNC_SIGNING_HEADERS.requestedAt]: String(auth.requestedAt),
                [CLOUDFLARE_SYNC_SIGNING_HEADERS.bodyHash]: auth.bodyHash,
                [CLOUDFLARE_SYNC_SIGNING_HEADERS.signatureAlg]: auth.signatureAlg,
                [CLOUDFLARE_SYNC_SIGNING_HEADERS.signatureKeyId]: auth.signatureKeyId,
                [CLOUDFLARE_SYNC_SIGNING_HEADERS.signature]: auth.signature
            },
            body: normalizedMethod === 'GET' ? undefined : bodyText
        })
        const json = await response.json().catch(() => null)
        if (!response.ok || json?.error) throw sanitizedCloudflareError(response, json)
        return {
            ...json,
            deviceSequence: sequence,
            metadataOnly: true
        }
    }

    function call(operation, { method = 'GET', body, deviceState, deviceSequence, params = {} } = {}) {
        return signedFetch({
            method,
            operation,
            path: operationPath(operation, params),
            body,
            deviceState,
            deviceSequence
        })
    }

    return {
        provider: 'cloudflare-d1-spike',
        call,
        bootstrapDesktop: options => call(CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop, {
            method: 'POST',
            body: { document: options.document },
            deviceState: options.deviceState,
            deviceSequence: options.deviceSequence
        }),
        requestEnrollment: options => call(CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment, {
            method: 'POST',
            body: { document: options.document, pairingChallengeHash: options.pairingChallengeHash },
            deviceState: options.deviceState,
            deviceSequence: options.deviceSequence
        }),
        listPendingEnrollments: options => call(CLOUDFLARE_SYNC_OPERATIONS.listPendingEnrollments, options),
        approveEnrollment: options => call(CLOUDFLARE_SYNC_OPERATIONS.approveEnrollment, {
            method: 'POST',
            body: { requestId: options.requestId, keyGrant: options.keyGrant },
            deviceState: options.deviceState,
            deviceSequence: options.deviceSequence
        }),
        claimEnrollment: options => call(CLOUDFLARE_SYNC_OPERATIONS.claimEnrollment, {
            method: 'POST',
            body: {
                requestId: options.requestId,
                keyGrantId: options.keyGrantId,
                pairingChallengeHash: options.pairingChallengeHash
            },
            deviceState: options.deviceState,
            deviceSequence: options.deviceSequence
        }),
        uploadSnapshot: options => call(CLOUDFLARE_SYNC_OPERATIONS.uploadSnapshot, {
            method: 'POST',
            body: { document: options.document },
            deviceState: options.deviceState,
            deviceSequence: options.deviceSequence
        }),
        getLatestSnapshot: options => call(CLOUDFLARE_SYNC_OPERATIONS.getLatestSnapshot, options),
        getSnapshot: options => call(CLOUDFLARE_SYNC_OPERATIONS.getSnapshot, {
            ...options,
            params: { revisionId: options.revisionId }
        }),
        uploadPatch: options => call(CLOUDFLARE_SYNC_OPERATIONS.uploadPatch, {
            method: 'POST',
            body: { document: options.document },
            deviceState: options.deviceState,
            deviceSequence: options.deviceSequence
        }),
        listPendingPatches: options => call(CLOUDFLARE_SYNC_OPERATIONS.listPendingPatches, options),
        getPatch: options => call(CLOUDFLARE_SYNC_OPERATIONS.getPatch, {
            ...options,
            params: { revisionId: options.revisionId }
        }),
        getDevice: options => call(CLOUDFLARE_SYNC_OPERATIONS.getDevice, {
            ...options,
            params: { deviceId: options.deviceId }
        }),
        recordPatchDecision: options => call(CLOUDFLARE_SYNC_OPERATIONS.recordPatchDecision, {
            method: 'POST',
            body: { decision: options.decision },
            deviceState: options.deviceState,
            deviceSequence: options.deviceSequence,
            params: { revisionId: options.revisionId || options.decision?.patchRevisionId }
        }),
        revokeDevice: options => call(CLOUDFLARE_SYNC_OPERATIONS.revokeDevice, {
            method: 'POST',
            body: {},
            deviceState: options.deviceState,
            deviceSequence: options.deviceSequence,
            params: { deviceId: options.deviceId }
        })
    }
}
