export const CLOUD_SYNC_CLIENT_STORAGE_VERSION = 1
export const CLOUD_SYNC_PHONE_KEY_PERSISTENCE = Object.freeze({
    indexedDbNonExtractable: 'indexeddb-non-extractable',
    sessionOnly: 'session-only'
})

const SECRET_FIELD_MARKERS = [
    'devicesessiontoken',
    'customtoken',
    'idtoken',
    'refreshtoken',
    'accesstoken',
    'bearertoken',
    'syncrootkey',
    'rootkeymaterial',
    'privatekey',
    'recovery',
    'password',
    'passcode',
    'backupcode',
    'cookie',
    'oauth',
    'credential',
    'fastboot',
    'hiddenmaster'
]

const AUTHORITY_FIELD_MARKERS = [
    'vault',
    'capability',
    'rawpath',
    'browserprofile',
    'browsersession',
    'launchauthority',
    'launchcapability',
    'shellcommand',
    'registrykey',
    'processid'
]

const OPAQUE_SAFE_VALUE_KEYS = new Set([
    'ciphertext',
    'ciphertexthash',
    'fingerprint',
    'grantid',
    'iv',
    'keygrantid',
    'salt',
    'spki',
    'tag',
    'value',
    'wrappedkeyciphertext',
    'wrappedkeyhash'
])

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function normalizedKey(value) {
    return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '')
}

function looksLikeForbiddenClientField(key) {
    const normalized = normalizedKey(key)
    if (normalized === 'pin' || normalized.endsWith('pin')) return true
    return SECRET_FIELD_MARKERS.some(marker => normalized.includes(marker)) ||
        AUTHORITY_FIELD_MARKERS.some(marker => normalized.includes(marker))
}

function looksLikeForbiddenClientString(value) {
    return /\bdeviceSessionToken\b/i.test(value) ||
        /\bbearer\s+[A-Za-z0-9._~+/-]{16,}/i.test(value) ||
        /\b(?:refresh|access|id|custom|device[_\s-]*session)[_\s-]*token\s*[:=]/i.test(value) ||
        /\b(?:sync[_\s-]*root[_\s-]*key|root[_\s-]*key[_\s-]*material|private[_\s-]*key|recovery[_\s-]*material)\s*[:=]/i.test(value) ||
        /\b(?:vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile|AppData[\\/])\b/i.test(value) ||
        /\bcap_[a-f0-9]{32,64}\b/i.test(value) ||
        /\b(?:password|passcode|backup\s*code|cookie|oauth|credential|pin|fastboot|hidden[_\s-]*master)\b\s*[:=]/i.test(value) ||
        /(?:^|[\s"'([{])(?:[A-Za-z]:[\\/]|\\\\|\[USB\][\\/])/i.test(value)
}

function shouldSkipOpaqueValue(key) {
    return OPAQUE_SAFE_VALUE_KEYS.has(normalizedKey(key))
}

export function assertNoForbiddenCloudSyncClientPlaintext(value, path = 'cloud sync client storage') {
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoForbiddenCloudSyncClientPlaintext(item, `${path}[${index}]`))
        return true
    }
    if (isPlainObject(value)) {
        for (const [key, nested] of Object.entries(value)) {
            if (looksLikeForbiddenClientField(key)) {
                fail(`${path}.${key} cannot be persisted or logged by cloud sync client storage.`)
            }
            if (!shouldSkipOpaqueValue(key)) {
                assertNoForbiddenCloudSyncClientPlaintext(nested, `${path}.${key}`)
            }
        }
        return true
    }
    if (typeof value === 'string' && looksLikeForbiddenClientString(value)) {
        fail(`${path} contains forbidden cloud sync client material.`)
    }
    return true
}

export function redactCloudSyncClientLogValue(value) {
    if (Array.isArray(value)) return value.map(redactCloudSyncClientLogValue)
    if (isPlainObject(value)) {
        const redacted = {}
        for (const [key, nested] of Object.entries(value)) {
            redacted[key] = looksLikeForbiddenClientField(key)
                ? '[REDACTED]'
                : redactCloudSyncClientLogValue(nested)
        }
        return redacted
    }
    if (typeof value === 'string' && looksLikeForbiddenClientString(value)) return '[REDACTED]'
    return value
}

function normalizeSafeId(value, fieldName, prefix) {
    if (typeof value !== 'string' || !value.startsWith(prefix) || value.length > 128) {
        fail(`${fieldName} must be a safe ${prefix} id.`)
    }
    if (!/^[A-Za-z][A-Za-z0-9_-]+$/.test(value)) fail(`${fieldName} must be a safe id.`)
    return value
}

function normalizeOwnerUid(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9:_-]{1,128}$/.test(value)) {
        fail('ownerUid must be a safe Firebase uid.')
    }
    return value
}

function normalizePositiveInteger(value, fieldName) {
    if (!Number.isSafeInteger(value) || value <= 0) fail(`${fieldName} must be a positive safe integer.`)
    return value
}

function normalizeNonNegativeInteger(value, fieldName) {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${fieldName} must be a non-negative safe integer.`)
    return value
}

function normalizeDeviceMetadata(input, fieldName = 'device') {
    const device = isPlainObject(input) ? input : fail(`${fieldName} is required.`)
    const role = String(device.role || '')
    if (!['desktop', 'phone', 'web-planner'].includes(role)) fail(`${fieldName}.role is not supported.`)
    return {
        ownerUid: normalizeOwnerUid(device.ownerUid),
        deviceId: normalizeSafeId(device.deviceId, `${fieldName}.deviceId`, 'dev_'),
        role,
        enrollmentEpoch: normalizePositiveInteger(device.enrollmentEpoch, `${fieldName}.enrollmentEpoch`),
        keyVersion: normalizePositiveInteger(device.keyVersion, `${fieldName}.keyVersion`),
        deviceSequence: normalizeNonNegativeInteger(device.deviceSequence, `${fieldName}.deviceSequence`)
    }
}

function assertNoRawToken(value) {
    if (!isPlainObject(value)) return
    for (const key of Object.keys(value)) {
        if (normalizedKey(key).includes('devicesessiontoken') || normalizedKey(key).includes('customtoken')) {
            fail('Raw device session tokens cannot be stored by cloud sync client storage.')
        }
    }
}

async function assertUnlocked(vaultAdapter) {
    if (!vaultAdapter || typeof vaultAdapter.loadCloudSyncState !== 'function') {
        fail('Desktop cloud sync storage requires a narrow vault-backed adapter.')
    }
    if (typeof vaultAdapter.isUnlocked === 'function' && !(await vaultAdapter.isUnlocked())) {
        fail('Desktop cloud sync storage is available only after vault unlock.')
    }
}

export function createDesktopCloudSyncStorage({ vaultAdapter } = {}) {
    return {
        async loadAfterUnlock() {
            await assertUnlocked(vaultAdapter)
            const state = await vaultAdapter.loadCloudSyncState()
            assertNoRawToken(state)
            const device = normalizeDeviceMetadata(state?.device, 'desktop cloud sync device')
            if (device.role !== 'desktop') fail('Desktop cloud sync storage requires a desktop device.')
            return { ...state, ownerUid: device.ownerUid, device }
        },
        async saveAfterUnlock(state) {
            await assertUnlocked(vaultAdapter)
            if (typeof vaultAdapter.saveCloudSyncState !== 'function') {
                fail('Desktop cloud sync storage adapter cannot save cloud sync state.')
            }
            assertNoRawToken(state)
            const device = normalizeDeviceMetadata(state?.device, 'desktop cloud sync device')
            if (device.role !== 'desktop') fail('Desktop cloud sync storage requires a desktop device.')
            await vaultAdapter.saveCloudSyncState({ ...state, ownerUid: device.ownerUid, device })
            return { status: 'saved', deviceId: device.deviceId }
        },
        async updateDeviceSequence(deviceSequence) {
            await assertUnlocked(vaultAdapter)
            if (typeof vaultAdapter.updateCloudSyncDeviceSequence !== 'function') return { status: 'skipped' }
            await vaultAdapter.updateCloudSyncDeviceSequence(normalizeNonNegativeInteger(deviceSequence, 'deviceSequence'))
            return { status: 'updated', deviceSequence }
        },
        debugSnapshot(state) {
            const device = state?.device ? normalizeDeviceMetadata(state.device, 'desktop cloud sync device') : null
            return {
                storageVersion: CLOUD_SYNC_CLIENT_STORAGE_VERSION,
                storage: 'desktop-vault-backed',
                unlockedRequired: true,
                device
            }
        }
    }
}

function keyLooksNonExtractable(key) {
    return !!key && typeof key === 'object' && key.extractable === false
}

function keyPairLooksNonExtractable(pair) {
    return !!pair &&
        keyLooksNonExtractable(pair.privateKey) &&
        !!pair.publicKey
}

async function putIndexedDb(adapter, storeName, key, value) {
    if (!adapter || typeof adapter.put !== 'function') fail('Phone cloud sync storage requires an IndexedDB adapter.')
    await adapter.put(storeName, key, value)
}

async function getIndexedDb(adapter, storeName, key) {
    if (!adapter || typeof adapter.get !== 'function') fail('Phone cloud sync storage requires an IndexedDB adapter.')
    return adapter.get(storeName, key)
}

export function createPhoneCloudSyncStorage({
    indexedDbAdapter,
    cryptoProvider,
    allowSessionOnlyKeys = false
} = {}) {
    const session = {
        device: null,
        signingPrivateKey: null,
        signingPublicKey: null,
        syncRootKey: null,
        keyPersistence: ''
    }

    return {
        async enrollDeviceKeys({ deviceId, now = Date.now() } = {}) {
            const safeDeviceId = normalizeSafeId(deviceId, 'deviceId', 'dev_')
            if (!cryptoProvider ||
                typeof cryptoProvider.generateSigningKeyPair !== 'function' ||
                typeof cryptoProvider.generateWrappingKeyPair !== 'function') {
                fail('Phone cloud sync storage requires a WebCrypto key provider.')
            }
            const signingKeyPair = await cryptoProvider.generateSigningKeyPair({ extractable: false })
            const wrappingKeyPair = await cryptoProvider.generateWrappingKeyPair({ extractable: false })
            const canPersist = cryptoProvider.supportsNonExtractableIndexedDbKeys === true &&
                keyPairLooksNonExtractable(signingKeyPair) &&
                keyPairLooksNonExtractable(wrappingKeyPair)

            if (!canPersist && !allowSessionOnlyKeys) {
                fail('Phone cloud sync storage requires non-extractable IndexedDB CryptoKey persistence.')
            }

            const keyPersistence = canPersist
                ? CLOUD_SYNC_PHONE_KEY_PERSISTENCE.indexedDbNonExtractable
                : CLOUD_SYNC_PHONE_KEY_PERSISTENCE.sessionOnly
            const metadata = {
                storageVersion: CLOUD_SYNC_CLIENT_STORAGE_VERSION,
                deviceId: safeDeviceId,
                keyPersistence,
                signingKeyRef: `signing:${safeDeviceId}`,
                wrappingKeyRef: `wrapping:${safeDeviceId}`,
                createdAt: now
            }
            assertNoForbiddenCloudSyncClientPlaintext(metadata)

            session.signingPrivateKey = signingKeyPair.privateKey
            session.signingPublicKey = signingKeyPair.publicKey
            session.keyPersistence = keyPersistence

            if (keyPersistence === CLOUD_SYNC_PHONE_KEY_PERSISTENCE.indexedDbNonExtractable) {
                await putIndexedDb(indexedDbAdapter, 'cloudSyncCryptoKeys', metadata.signingKeyRef, signingKeyPair.privateKey)
                await putIndexedDb(indexedDbAdapter, 'cloudSyncCryptoKeys', metadata.wrappingKeyRef, wrappingKeyPair.privateKey)
                await putIndexedDb(indexedDbAdapter, 'cloudSyncDeviceKeyMetadata', safeDeviceId, metadata)
            }
            return { ...metadata, signingPublicKey: signingKeyPair.publicKey, wrapPublicKey: wrappingKeyPair.publicKey }
        },
        async storeClaimedDeviceSessionMetadata({ ownerUid, device, keyGrantId, firebasePersistence = 'firebase-auth-sdk' } = {}) {
            const normalizedDevice = normalizeDeviceMetadata(device, 'phone cloud sync device')
            if (!['phone', 'web-planner'].includes(normalizedDevice.role)) {
                fail('Phone cloud sync storage requires a phone or web planner device.')
            }
            const metadata = {
                storageVersion: CLOUD_SYNC_CLIENT_STORAGE_VERSION,
                ownerUid: normalizeOwnerUid(ownerUid || normalizedDevice.ownerUid),
                device: normalizedDevice,
                keyGrantId: normalizeSafeId(keyGrantId, 'keyGrantId', 'grant_'),
                firebasePersistence,
                firebaseSdkOwnsPersistence: true
            }
            assertNoForbiddenCloudSyncClientPlaintext(metadata)
            await putIndexedDb(indexedDbAdapter, 'cloudSyncDeviceSessions', normalizedDevice.deviceId, metadata)
            session.device = normalizedDevice
            return clone(metadata)
        },
        async activateUnwrappedSyncKey({ ownerUid, device, keyVersion, syncRootKey, syncRootKeyRef = '' } = {}) {
            const normalizedDevice = normalizeDeviceMetadata(device, 'phone cloud sync device')
            const version = normalizePositiveInteger(keyVersion ?? normalizedDevice.keyVersion, 'keyVersion')
            session.device = normalizedDevice
            session.syncRootKey = syncRootKey
            const persisted = {
                storageVersion: CLOUD_SYNC_CLIENT_STORAGE_VERSION,
                ownerUid: normalizeOwnerUid(ownerUid || normalizedDevice.ownerUid),
                deviceId: normalizedDevice.deviceId,
                keyVersion: version,
                syncKeyRef: syncRootKeyRef || `sync-key:${normalizedDevice.deviceId}:v${version}`,
                rawKeyBytesStored: false
            }
            assertNoForbiddenCloudSyncClientPlaintext(persisted)
            await putIndexedDb(indexedDbAdapter, 'cloudSyncKeyMetadata', persisted.syncKeyRef, persisted)
            return clone(persisted)
        },
        async cacheEncryptedSnapshotEnvelope(envelope) {
            assertNoForbiddenCloudSyncClientPlaintext(envelope)
            await putIndexedDb(indexedDbAdapter, 'cloudSyncEncryptedSnapshots', envelope.revisionId, envelope)
            return { status: 'cached', revisionId: envelope.revisionId }
        },
        async cacheEncryptedPatchEnvelope(envelope) {
            assertNoForbiddenCloudSyncClientPlaintext(envelope)
            await putIndexedDb(indexedDbAdapter, 'cloudSyncEncryptedPatches', envelope.revisionId, envelope)
            return { status: 'cached', revisionId: envelope.revisionId }
        },
        async saveLocalDraftPatch(patch) {
            assertNoForbiddenCloudSyncClientPlaintext(patch)
            await putIndexedDb(indexedDbAdapter, 'cloudSyncLocalDraftPatches', patch.patchRevisionId, patch)
            return { status: 'saved', patchRevisionId: patch.patchRevisionId }
        },
        async loadSessionState() {
            if (session.device) {
                return {
                    device: clone(session.device),
                    syncRootKey: session.syncRootKey,
                    signingPrivateKey: session.signingPrivateKey,
                    signingPublicKey: session.signingPublicKey,
                    keyPersistence: session.keyPersistence
                }
            }
            return null
        },
        async loadPersistedSession(deviceId) {
            const safeDeviceId = normalizeSafeId(deviceId, 'deviceId', 'dev_')
            return getIndexedDb(indexedDbAdapter, 'cloudSyncDeviceSessions', safeDeviceId)
        },
        async updateDeviceSequence(deviceSequence) {
            if (!session.device) return { status: 'skipped' }
            session.device = {
                ...session.device,
                deviceSequence: normalizeNonNegativeInteger(deviceSequence, 'deviceSequence')
            }
            return { status: 'updated', deviceSequence }
        },
        debugSnapshot() {
            return {
                storageVersion: CLOUD_SYNC_CLIENT_STORAGE_VERSION,
                storage: 'phone-indexeddb-non-extractable',
                hasDevice: !!session.device,
                hasSyncKeyInMemory: !!session.syncRootKey,
                keyPersistence: session.keyPersistence || ''
            }
        }
    }
}
