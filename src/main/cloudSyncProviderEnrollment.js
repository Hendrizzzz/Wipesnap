import {
    approveCloudSyncDeviceEnrollmentAndGrantAfterUnlock,
    listPendingCloudSyncDeviceEnrollmentsAfterUnlock
} from './cloudSyncEnrollmentApproval.js'
import {
    approveCloudflareSyncEnrollmentAndGrantAfterUnlock,
    bootstrapCloudflareDesktopAfterUnlock,
    listPendingCloudflareSyncDeviceEnrollmentsAfterUnlock
} from './cloudSyncCloudflareTransport.js'
import { CLOUD_SYNC_PROVIDER_IDS } from './cloudSyncProviderPlan.js'

function sideEffectsNone(extra = {}) {
    return {
        writesVault: false,
        writesCapabilityVault: false,
        createsCapability: false,
        createsAccountSlots: false,
        createsBrowserProfiles: false,
        launches: false,
        writesCloudDeviceEnrollment: false,
        writesCloudKeyGrant: false,
        ...extra
    }
}

function provider(deps) {
    return deps?.cloudSyncRuntime?.provider || 'disabled'
}

function cloudflareSelected(deps) {
    return provider(deps) === CLOUD_SYNC_PROVIDER_IDS.cloudflare
}

function notConfigured(operation) {
    return {
        success: false,
        operation,
        status: 'not-configured',
        error: 'Cloudflare staging sync is not selected on this desktop.',
        records: [],
        summary: { pending: 0, approved: 0, granted: 0, skipped: 1 },
        metadataOnly: true,
        sideEffects: sideEffectsNone()
    }
}

export async function bootstrapCloudSyncDesktopDeviceAfterUnlockForProvider({
    deps
} = {}) {
    if (!cloudflareSelected(deps)) return notConfigured('bootstrap-cloudflare-desktop')
    return bootstrapCloudflareDesktopAfterUnlock({
        storage: deps.storage,
        cloudflareClient: deps.cloudflareClient
    })
}

export async function listPendingCloudSyncDeviceEnrollmentsAfterUnlockForProvider({
    deps
} = {}) {
    if (cloudflareSelected(deps)) {
        return listPendingCloudflareSyncDeviceEnrollmentsAfterUnlock({
            storage: deps.storage,
            cloudflareClient: deps.cloudflareClient
        })
    }
    return listPendingCloudSyncDeviceEnrollmentsAfterUnlock({
        storage: deps?.storage,
        functionsClient: deps?.functionsClient
    })
}

export async function approveCloudSyncDeviceEnrollmentAndGrantAfterUnlockForProvider({
    input = {},
    deps
} = {}) {
    if (cloudflareSelected(deps)) {
        return approveCloudflareSyncEnrollmentAndGrantAfterUnlock({
            input,
            storage: deps.storage,
            cloudflareClient: deps.cloudflareClient
        })
    }
    return approveCloudSyncDeviceEnrollmentAndGrantAfterUnlock({
        input,
        storage: deps?.storage,
        functionsClient: deps?.functionsClient
    })
}
