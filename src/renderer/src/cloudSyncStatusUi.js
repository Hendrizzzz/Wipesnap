const OPERATION_LABELS = {
    'upload-sanitized-snapshot': 'Snapshot upload',
    'download-encrypted-patch-summaries': 'Patch download',
    'plan-safe-preset-patches': 'Patch planning',
    'apply-trusted-patches': 'Trusted apply'
}

const STATUS_LABELS = {
    accepted: 'Uploaded',
    downloaded: 'Downloaded',
    planned: 'Planned',
    completed: 'Completed',
    locked: 'Locked',
    unavailable: 'Unavailable',
    rejected: 'Rejected',
    conflict: 'Conflict',
    skipped: 'Skipped',
    applied: 'Applied',
    'already-decided': 'Already decided'
}

const FORBIDDEN_STATUS_TEXT = /deviceSessionToken|bearer\s+|syncRootKey|rootKeyMaterial|privateKey|vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile|AppData[\\/]|cap_[a-f0-9]{32,64}|[A-Za-z]:[\\/]|\\\\|HKEY_|HKLM|HKCU|powershell|taskkill|cmd\s/i

function safeToken(value, fallback = 'unknown') {
    if (typeof value !== 'string') return fallback
    const text = value.trim()
    if (!text || text.length > 80 || FORBIDDEN_STATUS_TEXT.test(text)) return fallback
    if (!/^[A-Za-z0-9 _:-]+$/.test(text)) return fallback
    return text
}

function safeMessage(value, fallback) {
    if (typeof value !== 'string') return fallback
    const text = value.replace(/[\u0000-\u001F\u007F]/g, ' ').trim()
    if (!text || FORBIDDEN_STATUS_TEXT.test(text)) return fallback
    return text.length > 140 ? `${text.slice(0, 137).trim()}...` : text
}

function safeCount(value) {
    return Number.isSafeInteger(value) && value >= 0 ? value : 0
}

function statusLabel(status) {
    return STATUS_LABELS[status] || safeToken(status, 'Unknown')
}

function operationLabel(operation) {
    return OPERATION_LABELS[operation] || 'Cloud sync'
}

function defaultMessage(result, status) {
    if (result?.success === false) {
        if (status === 'locked') return 'Unlock the vault before using cloud sync.'
        if (status === 'unavailable') return 'Cloud sync is not configured on this desktop.'
        return 'Cloud sync did not complete.'
    }
    if (result?.operation === 'upload-sanitized-snapshot') return 'Sanitized snapshot uploaded.'
    if (result?.operation === 'download-encrypted-patch-summaries') return 'Encrypted patch summaries checked.'
    if (result?.operation === 'plan-safe-preset-patches') return 'Validate-only patch planning complete.'
    if (result?.operation === 'apply-trusted-patches') return 'Trusted patch apply complete.'
    return 'Cloud sync action complete.'
}

function summarizeRecord(record) {
    const status = safeToken(record?.status, 'unknown')
    const reason = safeToken(record?.reason || record?.code || '', '')
    return {
        status,
        statusLabel: statusLabel(status),
        reason,
        reasonLabel: reason ? statusLabel(reason) : '',
        encrypted: record?.encrypted === true,
        metadataOnly: true
    }
}

export function createCloudSyncStatusView(result) {
    if (!result || typeof result !== 'object' || Array.isArray(result)) {
        return {
            title: 'Cloud sync',
            status: 'idle',
            statusLabel: 'Idle',
            message: 'No cloud sync action has run.',
            counts: { uploaded: 0, downloaded: 0, planned: 0, applied: 0, conflicts: 0, skipped: 0 },
            records: [],
            metadataOnly: true
        }
    }

    const status = safeToken(result.status, result.success === false ? 'rejected' : 'completed')
    const summary = result.summary && typeof result.summary === 'object' ? result.summary : {}
    return {
        title: operationLabel(result.operation),
        status,
        statusLabel: statusLabel(status),
        message: safeMessage(result.error, defaultMessage(result, status)),
        counts: {
            uploaded: safeCount(summary.uploaded),
            downloaded: safeCount(summary.downloaded),
            planned: safeCount(summary.planned),
            applied: safeCount(summary.applied),
            conflicts: safeCount(summary.conflicts),
            skipped: safeCount(summary.skipped)
        },
        records: Array.isArray(result.records)
            ? result.records.slice(0, 5).map(summarizeRecord)
            : [],
        metadataOnly: true
    }
}

export function cloudSyncStatusViewContainsForbiddenMaterial(value) {
    const text = JSON.stringify(value || {})
    return FORBIDDEN_STATUS_TEXT.test(text) ||
        /ciphertext|importPlan|patchPayload|vaultData|devicePrivateKey|credential|browserSession|launchAuthority/i.test(text)
}
