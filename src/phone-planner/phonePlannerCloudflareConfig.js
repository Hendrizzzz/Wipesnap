import {
    CLOUDFLARE_SYNC_PROVIDER_ID,
    CLOUDFLARE_SYNC_STAGING_CONFIG_PROVIDER_ID
} from '../cloudflare-sync/cloudflareSyncConstants.js'

export const PHONE_PLANNER_CLOUDFLARE_CONFIG_URL = './cloudflare-sync-config.json'

const ALLOWED_CONFIG_KEYS = new Set([
    'environment',
    'provider',
    'requestedProvider',
    'apiBaseUrl',
    'useLocalDev',
    'maxEnvelopeJsonBytes'
])
const URL_PATTERN = /^https:\/\/[A-Za-z0-9.-]+(?:\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]*)?$/
const LOCAL_URL_PATTERN = /^http:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):\d{1,5}(?:\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]*)?$/

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function normalizedKey(value) {
    return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '')
}

function looksLikeForbiddenConfigKey(key) {
    const normalized = normalizedKey(key)
    return [
        'accountid',
        'apitoken',
        'apikey',
        'authorization',
        'bearer',
        'clientsecret',
        'credential',
        'deploymenttoken',
        'deviceprivatekey',
        'privatekey',
        'refreshtoken',
        'secret',
        'synckey',
        'syncrootkey',
        'token',
        'vault'
    ].some(marker => normalized.includes(marker))
}

function looksLikeForbiddenConfigString(value) {
    return /-----BEGIN [A-Z ]*PRIVATE KEY-----/i.test(value) ||
        /\b(?:bearer|api|refresh|access|id|deployment)[_\s-]*token\s*[:=]/i.test(value) ||
        /\b(?:sync[_\s-]*root[_\s-]*key|root[_\s-]*key[_\s-]*material|device[_\s-]*private[_\s-]*key)\s*[:=]/i.test(value) ||
        /\b(?:vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile|AppData[\\/])\b/i.test(value) ||
        /\bcap_[a-f0-9]{32,64}\b/i.test(value)
}

function assertNoForbiddenConfigMaterial(value, path = 'phone planner Cloudflare config') {
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoForbiddenConfigMaterial(item, `${path}[${index}]`))
        return
    }
    if (isPlainObject(value)) {
        for (const [key, nested] of Object.entries(value)) {
            if (looksLikeForbiddenConfigKey(key)) fail(`${path}.${key} cannot be present in hosted planner config.`)
            assertNoForbiddenConfigMaterial(nested, `${path}.${key}`)
        }
        return
    }
    if (typeof value === 'string' && looksLikeForbiddenConfigString(value)) {
        fail(`${path} contains forbidden secret or authority material.`)
    }
}

function requireString(value, fieldName, pattern, max = 240) {
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    const text = value.trim()
    if (!text || text.length > max) fail(`${fieldName} is required.`)
    if (pattern && !pattern.test(text)) fail(`${fieldName} is not a safe Cloudflare staging value.`)
    return text
}

function requireBoolean(value, fieldName, fallback = false) {
    if (value == null) return fallback
    if (typeof value !== 'boolean') fail(`${fieldName} must be a boolean.`)
    return value
}

function requireInteger(value, fieldName, { fallback, min, max }) {
    if (value == null) return fallback
    if (!Number.isSafeInteger(value) || value < min || value > max) {
        fail(`${fieldName} must be a safe integer between ${min} and ${max}.`)
    }
    return value
}

function normalizeApiBaseUrl(value, useLocalDev) {
    const text = requireString(
        value,
        'phone planner Cloudflare config.apiBaseUrl',
        useLocalDev ? LOCAL_URL_PATTERN : URL_PATTERN,
        240
    ).replace(/\/+$/g, '')
    if (!useLocalDev && /(?:^|[.-])prod(?:uction)?(?:[.-]|$)|wipesnap\.com/i.test(text)) {
        fail('Hosted phone planner refuses production-looking Cloudflare API URLs during the spike.')
    }
    return text
}

export function validatePhonePlannerCloudflareConfig(input) {
    if (!isPlainObject(input)) fail('Hosted phone planner Cloudflare config must be a JSON object.')
    assertNoForbiddenConfigMaterial(input)
    for (const key of Object.keys(input)) {
        if (!ALLOWED_CONFIG_KEYS.has(key)) {
            if (looksLikeForbiddenConfigKey(key)) fail(`phone planner Cloudflare config.${key} is forbidden.`)
            fail(`phone planner Cloudflare config.${key} is not supported.`)
        }
    }

    const environment = requireString(input.environment, 'phone planner Cloudflare config.environment', /^[a-z][a-z0-9-]{1,40}$/i, 40).toLowerCase()
    if (environment !== 'staging') fail('Hosted phone planner Cloudflare provider must use staging config.')
    const provider = requireString(input.provider, 'phone planner Cloudflare config.provider', /^[a-z0-9-]{1,80}$/i, 80)
    if (![CLOUDFLARE_SYNC_PROVIDER_ID, CLOUDFLARE_SYNC_STAGING_CONFIG_PROVIDER_ID].includes(provider)) {
        fail('Hosted phone planner Cloudflare provider id is not supported.')
    }
    const requestedProvider = input.requestedProvider == null
        ? provider
        : requireString(input.requestedProvider, 'phone planner Cloudflare config.requestedProvider', /^[a-z0-9-]{1,80}$/i, 80)
    if (![CLOUDFLARE_SYNC_PROVIDER_ID, CLOUDFLARE_SYNC_STAGING_CONFIG_PROVIDER_ID].includes(requestedProvider)) {
        fail('Hosted phone planner Cloudflare requested provider id is not supported.')
    }
    if (provider === CLOUDFLARE_SYNC_STAGING_CONFIG_PROVIDER_ID && requestedProvider !== provider) {
        fail('Hosted phone planner Cloudflare requested provider does not match the config provider.')
    }
    const useLocalDev = requireBoolean(input.useLocalDev, 'phone planner Cloudflare config.useLocalDev', false)
    return {
        environment,
        provider: CLOUDFLARE_SYNC_PROVIDER_ID,
        requestedProvider,
        apiBaseUrl: normalizeApiBaseUrl(input.apiBaseUrl, useLocalDev),
        useLocalDev,
        maxEnvelopeJsonBytes: requireInteger(input.maxEnvelopeJsonBytes, 'phone planner Cloudflare config.maxEnvelopeJsonBytes', {
            fallback: 768 * 1024,
            min: 1024,
            max: 768 * 1024
        })
    }
}

export async function loadPhonePlannerCloudflareConfig({
    fetchImpl = globalThis.fetch?.bind(globalThis),
    configUrl = PHONE_PLANNER_CLOUDFLARE_CONFIG_URL
} = {}) {
    if (typeof fetchImpl !== 'function') fail('Hosted phone planner cannot load Cloudflare config without fetch.')
    let response
    try {
        response = await fetchImpl(configUrl, { cache: 'no-store' })
    } catch (_) {
        fail('Hosted phone planner staging Cloudflare config is not available.')
    }
    if (!response || response.ok !== true) {
        fail('Hosted phone planner staging Cloudflare config is missing or unavailable.')
    }
    let json
    try {
        json = await response.json()
    } catch (_) {
        fail('Hosted phone planner staging Cloudflare config must be valid JSON.')
    }
    return validatePhonePlannerCloudflareConfig(json)
}
