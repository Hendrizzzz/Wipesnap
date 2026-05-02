import {
    PHONE_PLANNER_CLOUDFLARE_CONFIG_URL,
    validatePhonePlannerCloudflareConfig
} from './phonePlannerCloudflareConfig.js'
import {
    loadPhonePlannerFirebaseConfig,
    validatePhonePlannerFirebaseConfig
} from './phonePlannerFirebaseConfig.js'
import {
    CLOUDFLARE_SYNC_PROVIDER_ID,
    CLOUDFLARE_SYNC_STAGING_CONFIG_PROVIDER_ID
} from '../cloudflare-sync/cloudflareSyncConstants.js'

export const PHONE_PLANNER_CLOUD_PROVIDER_IDS = Object.freeze({
    firebase: 'firebase-staging',
    cloudflare: CLOUDFLARE_SYNC_PROVIDER_ID
})

export function validatePhonePlannerCloudProviderConfig(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw new Error('Hosted phone planner cloud provider config must be an object.')
    }
    const provider = input.provider || (input.projectId ? PHONE_PLANNER_CLOUD_PROVIDER_IDS.firebase : '')
    if (provider === PHONE_PLANNER_CLOUD_PROVIDER_IDS.firebase) {
        const { provider: _provider, ...firebaseConfig } = input
        return {
            provider: PHONE_PLANNER_CLOUD_PROVIDER_IDS.firebase,
            config: validatePhonePlannerFirebaseConfig(firebaseConfig)
        }
    }
    if (provider === PHONE_PLANNER_CLOUD_PROVIDER_IDS.cloudflare || provider === CLOUDFLARE_SYNC_STAGING_CONFIG_PROVIDER_ID) {
        return {
            provider: PHONE_PLANNER_CLOUD_PROVIDER_IDS.cloudflare,
            config: validatePhonePlannerCloudflareConfig(input)
        }
    }
    throw new Error('Hosted phone planner cloud provider is not supported.')
}

export function createPhonePlannerCloudProviderPlan(provider) {
    const providerId = typeof provider === 'string' ? provider : provider?.provider
    if (providerId === PHONE_PLANNER_CLOUD_PROVIDER_IDS.firebase) {
        return {
            provider: providerId,
            auth: 'firebase-auth-custom-claims',
            transport: 'callable-functions-firestore',
            migrationStatus: 'kept-for-phase31.1'
        }
    }
    if (providerId === PHONE_PLANNER_CLOUD_PROVIDER_IDS.cloudflare) {
        return {
            provider: providerId,
            auth: 'device-signed-canonical-requests',
            transport: 'workers-d1',
            migrationStatus: 'phase31.2-spike'
        }
    }
    throw new Error('Hosted phone planner cloud provider plan is not supported.')
}

export async function loadPhonePlannerCloudProviderConfig({
    fetchImpl = globalThis.fetch?.bind(globalThis),
    cloudflareConfigUrl = PHONE_PLANNER_CLOUDFLARE_CONFIG_URL
} = {}) {
    if (typeof fetchImpl !== 'function') throw new Error('Hosted phone planner cannot load cloud provider config without fetch.')
    let cloudflareResponse = null
    try {
        cloudflareResponse = await fetchImpl(cloudflareConfigUrl, { cache: 'no-store' })
    } catch (_) {
        cloudflareResponse = null
    }
    if (cloudflareResponse?.ok === true) {
        let json
        try {
            json = await cloudflareResponse.json()
        } catch (_) {
            throw new Error('Hosted phone planner Cloudflare staging config must be valid JSON.')
        }
        const selected = validatePhonePlannerCloudProviderConfig(json)
        if (selected.provider !== PHONE_PLANNER_CLOUD_PROVIDER_IDS.cloudflare) {
            throw new Error('Hosted phone planner Cloudflare config did not select Cloudflare.')
        }
        return selected
    }
    if (cloudflareResponse && cloudflareResponse.status !== 404) {
        throw new Error('Hosted phone planner Cloudflare staging config is unavailable.')
    }
    const firebaseConfig = await loadPhonePlannerFirebaseConfig({ fetchImpl })
    return {
        provider: PHONE_PLANNER_CLOUD_PROVIDER_IDS.firebase,
        config: firebaseConfig
    }
}
