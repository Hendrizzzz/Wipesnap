const ALLOWED_KEYS = new Set([
    'version',
    'enabled',
    'advancedPersonalMode',
    'localDesktopOverridePresetId',
    'acceptValidatedSelectionMetadata',
    'countdownSeconds'
])
const SAFE_PRESET_ID_PATTERN = /^preset_[A-Za-z0-9_-]{1,56}$/
const FORBIDDEN_TEXT = /https?:\/\/|[?#][A-Za-z0-9_=&%.-]+|deviceSessionToken|bearer\s+|syncRootKey|rootKeyMaterial|privateKey|vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile|AppData[\\/]|cap_[A-Za-z0-9_-]{4,128}|patchrev_[A-Za-z0-9_-]{4,128}|[A-Za-z]:[\\/]|\\\\|HKEY_|HKLM|HKCU|powershell|taskkill|cmd\s|ciphertext|cloudEnvelope|encryptedEnvelope|importPlan|launchPlan|patchPayload|vaultData|devicePrivateKey|credential|browserSession|launchAuthority/i

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function normalizedKey(value) {
    return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '')
}

function looksLikeForbiddenField(key) {
    const normalized = normalizedKey(key)
    return [
        'vault',
        'capability',
        'path',
        'appdata',
        'browserprofile',
        'browsersession',
        'process',
        'pid',
        'shell',
        'command',
        'registry',
        'token',
        'credential',
        'password',
        'passcode',
        'pin',
        'cookie',
        'oauth',
        'secret',
        'syncrootkey',
        'rootkeymaterial',
        'privatekey',
        'patchpayload',
        'cloudenvelope',
        'launchplan',
        'importplan'
    ].some(marker => normalized.includes(marker))
}

function assertNoForbiddenMaterial(value, path = 'trusted auto-launch setting') {
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoForbiddenMaterial(item, `${path}[${index}]`))
        return
    }
    if (isPlainObject(value)) {
        for (const [key, nested] of Object.entries(value)) {
            if (looksLikeForbiddenField(key)) fail(`${path}.${key} is not accepted.`)
            assertNoForbiddenMaterial(nested, `${path}.${key}`)
        }
        return
    }
    if (typeof value === 'string' && FORBIDDEN_TEXT.test(value)) {
        fail(`${path} contains forbidden material.`)
    }
}

function normalizeBoolean(value, fieldName) {
    if (typeof value !== 'boolean') fail(`${fieldName} must be a boolean.`)
    return value
}

function normalizePresetId(value, fieldName) {
    if (value == null || value === '') return null
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    const id = value.trim()
    if (!SAFE_PRESET_ID_PATTERN.test(id) || FORBIDDEN_TEXT.test(id)) {
        fail(`${fieldName} must be a safe preset id.`)
    }
    return id
}

function normalizeCountdownSeconds(value, fieldName) {
    if (!Number.isSafeInteger(value) || value < 3 || value > 30) {
        fail(`${fieldName} must be an integer from 3 to 30.`)
    }
    return value
}

export function validateTrustedAutoLaunchSettingPayload(value = {}) {
    if (!isPlainObject(value)) fail('trusted auto-launch setting must be an object.')
    assertNoForbiddenMaterial(value)
    for (const key of Object.keys(value)) {
        if (!ALLOWED_KEYS.has(key)) fail(`trusted auto-launch setting.${key} is not accepted.`)
    }
    const next = {}
    if ('version' in value) {
        if (value.version !== 1) fail('trusted auto-launch setting.version is not supported.')
        next.version = 1
    }
    if ('enabled' in value) next.enabled = normalizeBoolean(value.enabled, 'trusted auto-launch setting.enabled')
    if ('advancedPersonalMode' in value) {
        next.advancedPersonalMode = normalizeBoolean(value.advancedPersonalMode, 'trusted auto-launch setting.advancedPersonalMode')
    }
    if ('localDesktopOverridePresetId' in value) {
        next.localDesktopOverridePresetId = normalizePresetId(
            value.localDesktopOverridePresetId,
            'trusted auto-launch setting.localDesktopOverridePresetId'
        )
    }
    if ('acceptValidatedSelectionMetadata' in value) {
        next.acceptValidatedSelectionMetadata = normalizeBoolean(
            value.acceptValidatedSelectionMetadata,
            'trusted auto-launch setting.acceptValidatedSelectionMetadata'
        )
    }
    if ('countdownSeconds' in value) {
        next.countdownSeconds = normalizeCountdownSeconds(value.countdownSeconds, 'trusted auto-launch setting.countdownSeconds')
    }
    if (next.enabled === true && value.advancedPersonalMode !== true) {
        fail('trusted auto-launch requires advancedPersonalMode when enabled.')
    }
    return next
}
