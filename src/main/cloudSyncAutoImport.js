import { applyTrustedPatchesInvocationHandlerCore } from './cloudSyncInvocation.js'

export const CLOUD_SYNC_AUTO_IMPORT_OPERATION = 'auto-import-trusted-patches'

const FORBIDDEN_STATUS_TEXT = /deviceSessionToken|bearer\s+|syncRootKey|rootKeyMaterial|privateKey|vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile|AppData[\\/]|cap_[a-f0-9]{32,64}|[A-Za-z]:[\\/]|\\\\|HKEY_|HKLM|HKCU|powershell|taskkill|cmd\s|ciphertext|importPlan|patchPayload|vaultData|devicePrivateKey|credential|browserSession|launchAuthority/i
const SAFE_TOKEN_PATTERN = /^[a-z][a-z0-9-]{0,80}$/

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function safeCount(value) {
    return Number.isSafeInteger(value) && value >= 0 ? value : 0
}

function safeToken(value, fallback = 'unknown') {
    if (typeof value !== 'string') return fallback
    const token = value.trim().toLowerCase()
    if (!token || token.length > 80 || FORBIDDEN_STATUS_TEXT.test(token)) return fallback
    return SAFE_TOKEN_PATTERN.test(token) ? token : fallback
}

function sideEffectsNone(extra = {}) {
    return {
        writesVault: false,
        writesCapabilityVault: false,
        createsCapability: false,
        createsAccountSlots: false,
        createsBrowserProfiles: false,
        launches: false,
        writesCloudSnapshot: false,
        writesCloudPatchStatus: false,
        mergesPatch: false,
        ...extra
    }
}

function sanitizeSideEffects(sideEffects) {
    const value = isPlainObject(sideEffects) ? sideEffects : {}
    return sideEffectsNone({
        writesVault: value.writesVault === true,
        writesCapabilityVault: value.writesCapabilityVault === true,
        createsCapability: value.createsCapability === true,
        createsAccountSlots: value.createsAccountSlots === true,
        createsBrowserProfiles: value.createsBrowserProfiles === true,
        launches: value.launches === true,
        writesCloudSnapshot: value.writesCloudSnapshot === true,
        writesCloudPatchStatus: value.writesCloudPatchStatus === true,
        mergesPatch: value.mergesPatch === true
    })
}

function zeroSummary(extra = {}) {
    return {
        uploaded: 0,
        downloaded: 0,
        planned: 0,
        applied: 0,
        conflicts: 0,
        skipped: 0,
        ...extra
    }
}

function sanitizeSummary(summary) {
    const value = isPlainObject(summary) ? summary : {}
    return zeroSummary({
        uploaded: safeCount(value.uploaded),
        downloaded: safeCount(value.downloaded),
        planned: safeCount(value.planned),
        applied: safeCount(value.applied),
        conflicts: safeCount(value.conflicts),
        skipped: safeCount(value.skipped)
    })
}

function sanitizeCloudStatus(cloudStatus) {
    if (!isPlainObject(cloudStatus)) return null
    return {
        status: safeToken(cloudStatus.status),
        reason: safeToken(cloudStatus.reason || '', ''),
        metadataOnly: true
    }
}

function sanitizeRecord(record) {
    const value = isPlainObject(record) ? record : {}
    return {
        status: safeToken(value.status, 'skipped'),
        code: safeToken(value.code || '', ''),
        reason: safeToken(value.reason || value.code || '', ''),
        mergeStatus: safeToken(value.mergeStatus || '', ''),
        metadataOnly: true,
        cloudStatus: sanitizeCloudStatus(value.cloudStatus),
        sideEffects: sanitizeSideEffects(value.sideEffects)
    }
}

function autoImportFlags({ scheduled = false, running = false, attempted = false } = {}) {
    return {
        scheduled: scheduled === true,
        running: running === true,
        attempted: attempted === true,
        metadataOnly: true
    }
}

function baseStatus({ success = false, status, summary, records, sideEffects, autoImport } = {}) {
    return {
        success,
        operation: CLOUD_SYNC_AUTO_IMPORT_OPERATION,
        status: safeToken(status, 'idle'),
        metadataOnly: true,
        autoImport: autoImportFlags(autoImport),
        summary: sanitizeSummary(summary),
        records: Array.isArray(records) ? records.slice(0, 20).map(sanitizeRecord) : [],
        sideEffects: sanitizeSideEffects(sideEffects)
    }
}

function isLockedError(error) {
    return /session is locked|vault is locked|locked vault|unlock required|after vault unlock|active vault session|unlock/i
        .test(error?.message || '')
}

function isRuntimeUnavailableError(error) {
    return /cloud sync (invocation|transport).*requires|requires (unlocked desktop cloud sync storage|desktop cloud sync storage|a Functions client|a Firestore client|a current sanitized snapshot builder)|cannot (call|read|list) cloud sync|runtime is not configured/i
        .test(error?.message || '')
}

export function createTrustedAutoImportIdleStatus() {
    return baseStatus({
        status: 'idle',
        summary: zeroSummary(),
        records: [],
        sideEffects: sideEffectsNone(),
        autoImport: { scheduled: false, running: false, attempted: false }
    })
}

export function createTrustedAutoImportScheduledStatus({ running = false } = {}) {
    return baseStatus({
        status: running ? 'running' : 'scheduled',
        summary: zeroSummary(),
        records: [],
        sideEffects: sideEffectsNone(),
        autoImport: { scheduled: true, running, attempted: false }
    })
}

export function sanitizeTrustedAutoImportResult(result) {
    const value = isPlainObject(result) ? result : {}
    const status = safeToken(value.status, value.success === false ? 'rejected' : 'completed')
    return baseStatus({
        success: value.success === false ? false : status === 'completed',
        status,
        summary: sanitizeSummary(value.summary),
        records: value.records,
        sideEffects: value.sideEffects,
        autoImport: { scheduled: false, running: false, attempted: true }
    })
}

export function sanitizeTrustedAutoImportError(error) {
    const status = isLockedError(error)
        ? 'locked'
        : isRuntimeUnavailableError(error)
            ? 'unavailable'
            : 'rejected'
    return baseStatus({
        success: false,
        status,
        summary: zeroSummary(),
        records: [],
        sideEffects: sideEffectsNone(),
        autoImport: { scheduled: false, running: false, attempted: true }
    })
}

export function cloudSyncAutoImportStatusContainsForbiddenMaterial(value) {
    const forbiddenKeys = new Set([
        'patchRevisionId',
        'patchId',
        'authorDeviceId',
        'baseSnapshotRevisionId',
        'currentSnapshotRevisionId',
        'ciphertext',
        'envelope',
        'payload',
        'importPlan',
        'patchPayload',
        'vaultPath',
        'capabilityId',
        'token',
        'syncRootKey',
        'rootKeyMaterial',
        'privateKey',
        'credential',
        'browserSession',
        'launchAuthority'
    ])
    const scan = (candidate) => {
        if (Array.isArray(candidate)) return candidate.some(scan)
        if (isPlainObject(candidate)) {
            return Object.entries(candidate).some(([key, nested]) =>
                forbiddenKeys.has(key) || scan(nested)
            )
        }
        return typeof candidate === 'string' && FORBIDDEN_STATUS_TEXT.test(candidate)
    }
    return scan(value)
}

export function createTrustedAutoImportOrchestrator({
    resolveDeps,
    applyHandler = applyTrustedPatchesInvocationHandlerCore,
    schedule = (callback) => setTimeout(callback, 0),
    onStatus = () => {},
    logger = null
} = {}) {
    if (typeof resolveDeps !== 'function') fail('Trusted auto-import requires dependency resolver.')
    if (typeof applyHandler !== 'function') fail('Trusted auto-import requires an apply handler.')
    if (typeof schedule !== 'function') fail('Trusted auto-import requires a scheduler.')

    let sessionWindowId = 0
    let running = false
    let lastStatus = createTrustedAutoImportIdleStatus()
    const attemptedSessionIds = new Set()
    const queuedSessionIds = []

    const emit = (status) => {
        lastStatus = clone(status)
        try {
            onStatus(clone(lastStatus))
        } catch (error) {
            if (logger?.warn) logger.warn('[Wipesnap] trusted auto-import status emit failed:', error?.message || error)
        }
        return clone(lastStatus)
    }

    const runQueued = () => {
        const nextSessionId = queuedSessionIds.find(id => !attemptedSessionIds.has(id))
        if (!nextSessionId) return
        const remaining = queuedSessionIds.filter(id => id !== nextSessionId)
        queuedSessionIds.length = 0
        queuedSessionIds.push(...remaining)
        scheduleRun(nextSessionId)
    }

    const runForSession = async (sessionId) => {
        if (!Number.isSafeInteger(sessionId) || sessionId < 1) {
            return emit(sanitizeTrustedAutoImportError(new Error('Session is locked')))
        }
        if (attemptedSessionIds.has(sessionId)) return clone(lastStatus)
        if (running) {
            if (!queuedSessionIds.includes(sessionId)) queuedSessionIds.push(sessionId)
            return clone(lastStatus)
        }

        attemptedSessionIds.add(sessionId)
        running = true
        emit(baseStatus({
            status: 'running',
            summary: zeroSummary(),
            records: [],
            sideEffects: sideEffectsNone(),
            autoImport: { scheduled: true, running: true, attempted: true }
        }))

        try {
            const result = await applyHandler({
                input: {},
                deps: resolveDeps()
            })
            return emit(sanitizeTrustedAutoImportResult(result))
        } catch (error) {
            if (logger?.warn) logger.warn('[Wipesnap] trusted auto-import failed:', error?.message || error)
            return emit(sanitizeTrustedAutoImportError(error))
        } finally {
            running = false
            runQueued()
        }
    }

    function scheduleRun(sessionId) {
        try {
            schedule(() => {
                Promise.resolve(runForSession(sessionId)).catch(error => {
                    emit(sanitizeTrustedAutoImportError(error))
                })
            })
        } catch (error) {
            Promise.resolve(runForSession(sessionId)).catch(runError => {
                emit(sanitizeTrustedAutoImportError(runError))
            })
        }
    }

    function beginUnlockSession() {
        sessionWindowId += 1
        return sessionWindowId
    }

    return {
        scheduleAfterUnlock() {
            const sessionId = beginUnlockSession()
            emit(createTrustedAutoImportScheduledStatus({ running }))
            scheduleRun(sessionId)
            return clone(lastStatus)
        },
        runAfterUnlock() {
            const sessionId = beginUnlockSession()
            emit(createTrustedAutoImportScheduledStatus({ running }))
            return runForSession(sessionId)
        },
        markLocked() {
            queuedSessionIds.length = 0
            return emit(baseStatus({
                success: false,
                status: 'locked',
                summary: zeroSummary(),
                records: [],
                sideEffects: sideEffectsNone(),
                autoImport: { scheduled: false, running, attempted: false }
            }))
        },
        getStatus() {
            return clone(lastStatus)
        }
    }
}
