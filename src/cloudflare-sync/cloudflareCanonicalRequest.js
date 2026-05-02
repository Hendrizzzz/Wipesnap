import {
    CLOUDFLARE_SYNC_CANONICAL_REQUEST_VERSION,
    CLOUDFLARE_SYNC_PROVIDER_ID,
    CLOUDFLARE_SYNC_SIGNING_HEADERS
} from './cloudflareSyncConstants.js'

const CLOUD_SYNC_SIGNING_ALGORITHM = 'ECDSA-P256-SHA256-P1363'
const OWNER_UID_PATTERN = /^[A-Za-z0-9:_-]{1,128}$/
const DEVICE_ID_PATTERN = /^dev_[A-Za-z0-9_-]{1,92}$/
const SAFE_ROLE_PATTERN = /^(?:desktop|phone|web-planner)$/
const SAFE_OPERATION_PATTERN = /^[a-z][a-z0-9-]{1,80}$/
const SAFE_PATH_PATTERN = /^\/v1\/[A-Za-z0-9_./?=&%-]{1,220}$/
const HASH_PATTERN = /^[A-Za-z0-9_-]{32,128}$/
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/

const textEncoder = new TextEncoder()

function fail(message) {
    throw new Error(message)
}

function requireString(value, fieldName, pattern, max = 256) {
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    const text = value.trim()
    if (!text || text.length > max) fail(`${fieldName} is required.`)
    if (pattern && !pattern.test(text)) fail(`${fieldName} is not safe.`)
    return text
}

function requireInteger(value, fieldName, { positive = false } = {}) {
    const number = typeof value === 'string' && value.trim() ? Number(value.trim()) : value
    if (!Number.isSafeInteger(number) || number < (positive ? 1 : 0)) {
        fail(`${fieldName} must be a ${positive ? 'positive' : 'non-negative'} safe integer.`)
    }
    return number
}

function base64Decode(value) {
    if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(value, 'base64'))
    const binary = atob(value)
    const bytes = new Uint8Array(binary.length)
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
    return bytes
}

function base64UrlDecode(value, fieldName) {
    const text = requireString(value, fieldName, BASE64URL_PATTERN, 8192)
    const padded = text.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(text.length / 4) * 4, '=')
    return base64Decode(padded)
}

function bytesFrom(value) {
    if (value instanceof Uint8Array) return value
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    if (value instanceof ArrayBuffer) return new Uint8Array(value)
    if (typeof value === 'string') return textEncoder.encode(value)
    return textEncoder.encode(JSON.stringify(value ?? null))
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function canonicalizeCloudflareValue(value) {
    if (Array.isArray(value)) return value.map(canonicalizeCloudflareValue)
    if (isPlainObject(value)) {
        const next = {}
        for (const key of Object.keys(value).sort()) {
            const nested = value[key]
            next[key] = nested === undefined ? null : canonicalizeCloudflareValue(nested)
        }
        return next
    }
    if (value === undefined) return null
    if (typeof value === 'number' && !Number.isFinite(value)) fail('Canonical Cloudflare sync numbers must be finite.')
    return value
}

function serializeCanonicalCloudflareMetadata(value) {
    return JSON.stringify(canonicalizeCloudflareValue(value))
}

function encodeBase64Url(bytes) {
    const input = bytesFrom(bytes)
    if (typeof Buffer !== 'undefined') return Buffer.from(input).toString('base64url')
    let binary = ''
    for (let index = 0; index < input.length; index += 0x8000) {
        binary += String.fromCharCode(...input.slice(index, index + 0x8000))
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function headerValue(headers, name) {
    if (!headers) return ''
    if (typeof headers.get === 'function') return headers.get(name) || ''
    const key = Object.keys(headers).find(candidate => candidate.toLowerCase() === name.toLowerCase())
    return key ? headers[key] : ''
}

export async function sha256Base64Url(value, cryptoApi = globalThis.crypto) {
    if (!cryptoApi?.subtle) fail('Cloudflare sync canonical requests require WebCrypto SHA-256.')
    const digest = await cryptoApi.subtle.digest('SHA-256', bytesFrom(value))
    return encodeBase64Url(new Uint8Array(digest))
}

export function normalizeCloudflareRequestAuth(input = {}) {
    return {
        ownerUid: requireString(input.ownerUid, 'ownerUid', OWNER_UID_PATTERN, 128),
        deviceId: requireString(input.deviceId, 'deviceId', DEVICE_ID_PATTERN, 96),
        deviceRole: requireString(input.deviceRole, 'deviceRole', SAFE_ROLE_PATTERN, 40),
        enrollmentEpoch: requireInteger(input.enrollmentEpoch, 'enrollmentEpoch', { positive: true }),
        keyVersion: requireInteger(input.keyVersion, 'keyVersion', { positive: true }),
        deviceSequence: requireInteger(input.deviceSequence, 'deviceSequence'),
        requestedAt: requireInteger(input.requestedAt, 'requestedAt'),
        bodyHash: requireString(input.bodyHash, 'bodyHash', HASH_PATTERN, 128),
        signatureAlg: requireString(input.signatureAlg, 'signatureAlg', /^ECDSA-P256-SHA256-P1363$/, 40),
        signatureKeyId: requireString(input.signatureKeyId, 'signatureKeyId', DEVICE_ID_PATTERN, 96),
        signature: requireString(input.signature, 'signature', BASE64URL_PATTERN, 8192)
    }
}

export function cloudflareRequestAuthFromHeaders(headers) {
    return normalizeCloudflareRequestAuth({
        ownerUid: headerValue(headers, CLOUDFLARE_SYNC_SIGNING_HEADERS.ownerUid),
        deviceId: headerValue(headers, CLOUDFLARE_SYNC_SIGNING_HEADERS.deviceId),
        deviceRole: headerValue(headers, CLOUDFLARE_SYNC_SIGNING_HEADERS.deviceRole),
        enrollmentEpoch: headerValue(headers, CLOUDFLARE_SYNC_SIGNING_HEADERS.enrollmentEpoch),
        keyVersion: headerValue(headers, CLOUDFLARE_SYNC_SIGNING_HEADERS.keyVersion),
        deviceSequence: headerValue(headers, CLOUDFLARE_SYNC_SIGNING_HEADERS.deviceSequence),
        requestedAt: headerValue(headers, CLOUDFLARE_SYNC_SIGNING_HEADERS.requestedAt),
        bodyHash: headerValue(headers, CLOUDFLARE_SYNC_SIGNING_HEADERS.bodyHash),
        signatureAlg: headerValue(headers, CLOUDFLARE_SYNC_SIGNING_HEADERS.signatureAlg),
        signatureKeyId: headerValue(headers, CLOUDFLARE_SYNC_SIGNING_HEADERS.signatureKeyId),
        signature: headerValue(headers, CLOUDFLARE_SYNC_SIGNING_HEADERS.signature)
    })
}

export function createCloudflareCanonicalRequestMetadata(input = {}) {
    const auth = normalizeCloudflareRequestAuth({ ...input, signature: input.signature || 'A' })
    const method = requireString(input.method, 'method', /^(?:GET|POST)$/, 8).toUpperCase()
    const path = requireString(input.path, 'path', SAFE_PATH_PATTERN, 240)
    const operation = requireString(input.operation, 'operation', SAFE_OPERATION_PATTERN, 80)
    return serializeCanonicalCloudflareMetadata({
        product: 'wipesnap',
        provider: CLOUDFLARE_SYNC_PROVIDER_ID,
        schemaVersion: CLOUDFLARE_SYNC_CANONICAL_REQUEST_VERSION,
        operation,
        method,
        path,
        ownerUid: auth.ownerUid,
        deviceId: auth.deviceId,
        deviceRole: auth.deviceRole,
        deviceSequence: auth.deviceSequence,
        enrollmentEpoch: auth.enrollmentEpoch,
        keyVersion: auth.keyVersion,
        requestedAt: auth.requestedAt,
        bodyHash: auth.bodyHash
    })
}

export async function importCloudflareSigningPublicKey(publicKeyRecord, cryptoApi = globalThis.crypto) {
    if (!cryptoApi?.subtle) fail('Cloudflare sync signature verification requires WebCrypto.')
    if (!publicKeyRecord || publicKeyRecord.alg !== CLOUD_SYNC_SIGNING_ALGORITHM) {
        fail('Cloudflare sync signing public key algorithm is not supported.')
    }
    return cryptoApi.subtle.importKey(
        'spki',
        base64UrlDecode(publicKeyRecord.spki, 'signingPublicKey.spki'),
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
    )
}

export async function verifyCloudflareCanonicalRequest({
    canonicalMetadata,
    signature,
    publicKeyRecord,
    cryptoApi = globalThis.crypto
} = {}) {
    const key = await importCloudflareSigningPublicKey(publicKeyRecord, cryptoApi)
    const bytes = base64UrlDecode(signature, 'signature')
    if (bytes.length !== 64) fail('Cloudflare sync request signature must be 64-byte P1363 data.')
    return cryptoApi.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        bytes,
        textEncoder.encode(canonicalMetadata)
    )
}
