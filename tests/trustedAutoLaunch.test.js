import assert from 'assert/strict'
import { test } from 'node:test'
import { createCapabilityRecord } from '../src/main/capabilityStore.js'
import {
    TRUSTED_AUTO_LAUNCH_SETTINGS_KEY,
    TRUSTED_AUTO_LAUNCH_STATE_KEY,
    createTrustedAutoLaunchOrchestrator,
    defaultTrustedAutoLaunchSetting,
    trustedAutoImportStatusIsClean,
    trustedAutoLaunchStatusContainsForbiddenMaterial,
    validateTrustedAutoLaunchSetting
} from '../src/main/trustedAutoLaunch.js'
import { WORKSPACE_CAPABILITY_VAULT_KEY } from '../src/main/workspaceCapabilityMigration.js'
import { WORKSPACE_SAFE_PRESET_METADATA_KEY } from '../src/main/safePresetMetadata.js'

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function cleanAutoImport(records = []) {
    return {
        success: true,
        operation: 'auto-import-trusted-patches',
        status: 'completed',
        statusCategory: records.length ? 'applied' : 'no-patches',
        records,
        summary: {
            applied: records.filter(record => record.status === 'applied').length,
            conflicts: 0,
            skipped: records.filter(record => record.status === 'skipped').length
        },
        metadataOnly: true
    }
}

function failedAutoImport(category, record = {}) {
    return {
        success: false,
        operation: 'auto-import-trusted-patches',
        status: 'completed',
        statusCategory: category,
        records: [{
            status: record.status || (category === 'conflict' || category === 'stale-base' ? 'conflict' : 'skipped'),
            code: record.code || category,
            reason: record.reason || category,
            metadataOnly: true
        }],
        summary: { applied: 0, conflicts: category === 'conflict' ? 1 : 0, skipped: category === 'conflict' ? 0 : 1 },
        metadataOnly: true
    }
}

function basePreset(id, itemId = 'item_tab') {
    return {
        id,
        name: id.replace(/^preset_/, ''),
        order: 0,
        enabled: true,
        itemRefs: [{
            id: `pref_${id.replace(/^preset_/, '')}_${itemId.replace(/^(?:item_|patch_item_|accti_|profi_)/, '')}`,
            itemId,
            order: 0,
            enabled: true,
            metadataOnly: true
        }]
    }
}

function baseSnapshot(overrides = {}) {
    return {
        product: 'wipesnap',
        kind: 'sanitized-preset-snapshot',
        schemaVersion: 1,
        snapshotId: 'snap_phase30',
        revisionId: 'srev_phase30_1',
        sourceDeviceId: 'dev_desktop_phase30',
        timestamp: 1770000000000,
        limits: {},
        selection: {
            defaultPresetId: null,
            nextPresetId: null,
            metadataOnly: true,
            selectionKind: 'metadata-only'
        },
        presets: [basePreset('preset_local')],
        availableItems: [{
            id: 'item_tab',
            type: 'browser-tab',
            label: 'Docs',
            status: 'available',
            source: 'browser',
            url: 'https://example.com/'
        }],
        ...overrides
    }
}

function metadataFixture({
    defaultPresetId = 'preset_default',
    nextPresetId = 'preset_next',
    patchRevisionId = 'patchrev_phase30_1',
    presets = ['preset_next', 'preset_default']
} = {}) {
    return {
        version: 1,
        metadataOnly: true,
        source: 'safe-preset-patch-merge',
        lastMergedPatchId: 'patch_phase30',
        lastMergedPatchRevisionId: patchRevisionId,
        baseSnapshotRevisionId: 'srev_base',
        mergedAt: 1770000000001,
        selection: {
            defaultPresetId,
            nextPresetId,
            metadataOnly: true,
            selectionKind: 'metadata-only'
        },
        presets: presets.map((id, index) => ({
            id,
            name: id.replace(/^preset_/, ''),
            order: index,
            enabled: true,
            itemRefs: [{
                id: `pref_${id.replace(/^preset_/, '')}`,
                itemId: 'item_tab',
                order: 0,
                enabled: true,
                metadataOnly: true
            }],
            metadataOnly: true
        })),
        newBrowserItems: []
    }
}

function baseWorkspace(overrides = {}) {
    return {
        name: 'Phase 30',
        webTabs: [{
            url: 'https://example.com/',
            label: 'Docs',
            enabled: true
        }],
        desktopApps: [],
        ...overrides
    }
}

function enabledSetting(overrides = {}) {
    return {
        version: 1,
        enabled: true,
        advancedPersonalMode: true,
        localDesktopOverridePresetId: 'preset_local',
        acceptValidatedSelectionMetadata: false,
        countdownSeconds: 3,
        ...overrides
    }
}

function createScheduler() {
    const queued = []
    return {
        schedule(callback) {
            queued.push(callback)
            return callback
        },
        clearScheduled(handle) {
            const index = queued.indexOf(handle)
            if (index >= 0) queued.splice(index, 1)
        },
        async runNext() {
            const callback = queued.shift()
            if (callback) await callback()
        },
        async runAll(limit = 10) {
            for (let i = 0; i < limit && queued.length > 0; i += 1) {
                await this.runNext()
            }
        },
        get size() {
            return queued.length
        }
    }
}

function createHarness(options = {}) {
    const scheduler = createScheduler()
    const calls = {
        statuses: [],
        launches: [],
        launchContexts: [],
        prepared: [],
        metaWrites: 0,
        snapshotBuilds: 0,
        authorChecks: 0
    }
    const state = {
        locked: false,
        meta: {
            version: '1.0.0',
            [TRUSTED_AUTO_LAUNCH_SETTINGS_KEY]: enabledSetting(options.setting || {})
        },
        workspace: options.workspace || baseWorkspace(),
        snapshot: options.snapshot || baseSnapshot(),
        healthStatus: options.healthStatus || 'ready',
        browserReady: options.browserReady !== false,
        launchActive: options.launchActive === true,
        authorTrusted: options.authorTrusted !== false,
        authorTrustResult: options.authorTrustResult || null,
        hostUnavailable: options.hostUnavailable === true
    }
    const deps = {
        requireActiveSession: () => {
            if (state.locked) throw new Error('Session is locked')
        },
        loadActiveVaultWorkspace: () => clone(state.workspace),
        loadVaultMeta: () => clone(state.meta),
        saveVaultMeta: (nextMeta) => {
            calls.metaWrites += 1
            state.meta = clone(nextMeta)
        },
        getVaultDir: () => 'C:\\WipesnapTestVault',
        buildCurrentSanitizedSnapshot: async (context) => {
            calls.snapshotBuilds += 1
            if (typeof options.buildCurrentSanitizedSnapshot === 'function') {
                return clone(await options.buildCurrentSanitizedSnapshot({
                    ...context,
                    state,
                    calls
                }))
            }
            return clone(state.snapshot)
        },
        loadWorkspaceHealthSummary: () => ({
            success: state.healthStatus === 'ready',
            available: state.healthStatus === 'ready',
            status: state.healthStatus,
            state: state.healthStatus
        }),
        browserProfileReady: () => state.browserReady,
        manifestResolver: () => null,
        prepareLaunchWorkspaceConfig: async (workspace, prepareOptions) => {
            const prepared = typeof options.prepareLaunchWorkspaceConfig === 'function'
                ? clone(await options.prepareLaunchWorkspaceConfig({
                    workspace: clone(workspace),
                    prepareOptions,
                    state,
                    calls
                }))
                : clone(workspace)
            if (state.hostUnavailable && prepared.desktopApps[0]) {
                prepared.desktopApps[0] = {
                    ...prepared.desktopApps[0],
                    availabilityStatus: 'missing-on-this-PC',
                    hostResolution: { status: 'missing-on-this-PC', metadataOnly: true }
                }
            }
            calls.prepared.push(clone(prepared))
            return prepared
        },
        isLaunchActive: () => state.launchActive,
        verifyMergedPatchAuthor: async () => {
            calls.authorChecks += 1
            if (state.authorTrustResult) return clone(state.authorTrustResult)
            return state.authorTrusted
                ? { trusted: true, metadataOnly: true }
                : { trusted: false, reason: 'revoked-device', metadataOnly: true }
        },
        launchWorkspace: async (workspace, context) => {
            calls.launches.push(clone(workspace))
            calls.launchContexts.push(clone(context))
            return {
                webResults: (workspace.webTabs || []).map(tab => ({ type: 'web', url: tab.url, success: true })),
                appResults: (workspace.desktopApps || []).map(app => ({ type: 'app', name: app.name, success: true }))
            }
        }
    }
    const autoLaunch = createTrustedAutoLaunchOrchestrator({
        deps,
        schedule: scheduler.schedule,
        clearScheduled: scheduler.clearScheduled,
        onStatus: (status) => calls.statuses.push(clone(status))
    })
    return {
        autoLaunch,
        scheduler,
        calls,
        state,
        async unlockAndClean(status = cleanAutoImport()) {
            autoLaunch.beginUnlockSession()
            await autoLaunch.observeAutoImportStatus(status)
        },
        lastStatus() {
            return calls.statuses[calls.statuses.length - 1]
        }
    }
}

async function runCountdown(harness) {
    await harness.scheduler.runAll(5)
}

function assertBlocked(harness, code) {
    const status = harness.lastStatus()
    assert.equal(status.statusCategory, 'blocked')
    assert.ok(status.blockerReasonCodes.includes(code), `expected blocker ${code}, got ${status.blockerReasonCodes.join(', ')}`)
}

test('trusted auto-launch settings are off by default and reject unsafe payloads', () => {
    assert.equal(defaultTrustedAutoLaunchSetting().enabled, false)
    assert.deepEqual(validateTrustedAutoLaunchSetting({
        version: 1,
        enabled: true,
        advancedPersonalMode: true,
        localDesktopOverridePresetId: 'preset_local',
        acceptValidatedSelectionMetadata: true,
        countdownSeconds: 5
    }), {
        version: 1,
        enabled: true,
        advancedPersonalMode: true,
        localDesktopOverridePresetId: 'preset_local',
        acceptValidatedSelectionMetadata: true,
        countdownSeconds: 5
    })
    assert.throws(() => validateTrustedAutoLaunchSetting({ enabled: true }), /advancedPersonalMode/)
    assert.throws(() => validateTrustedAutoLaunchSetting({ enabled: false, path: 'C:\\secret\\app.exe' }), /not accepted|schema/)
    assert.throws(() => validateTrustedAutoLaunchSetting({
        enabled: true,
        advancedPersonalMode: true,
        localDesktopOverridePresetId: 'cap_1234567890abcdef1234567890abcdef'
    }), /safe preset id|forbidden/)
    assert.throws(() => validateTrustedAutoLaunchSetting({
        enabled: true,
        advancedPersonalMode: true,
        localDesktopOverridePresetId: 'https://example.com'
    }), /safe preset id|forbidden/)
})

test('local desktop override has priority over accepted metadata targets', async () => {
    const metadata = metadataFixture()
    const harness = createHarness({
        setting: {
            localDesktopOverridePresetId: 'preset_local',
            acceptValidatedSelectionMetadata: true
        },
        workspace: baseWorkspace({ [WORKSPACE_SAFE_PRESET_METADATA_KEY]: metadata }),
        snapshot: baseSnapshot({
            presets: [basePreset('preset_local'), basePreset('preset_next'), basePreset('preset_default')]
        })
    })
    await harness.unlockAndClean()
    assert.equal(harness.lastStatus().statusCategory, 'countdown')
    assert.equal(harness.lastStatus().presetLabel, 'local')
    await runCountdown(harness)
    assert.equal(harness.calls.launches.length, 1)
    assert.equal(harness.calls.authorChecks, 0)
})

test('accepted nextPresetId is one-time per merged patch revision, then defaultPresetId is used', async () => {
    const metadata = metadataFixture()
    const harness = createHarness({
        setting: {
            localDesktopOverridePresetId: null,
            acceptValidatedSelectionMetadata: true
        },
        workspace: baseWorkspace({ [WORKSPACE_SAFE_PRESET_METADATA_KEY]: metadata }),
        snapshot: baseSnapshot({
            presets: [basePreset('preset_next'), basePreset('preset_default')]
        })
    })
    await harness.unlockAndClean()
    assert.equal(harness.lastStatus().statusCategory, 'countdown')
    assert.equal(harness.lastStatus().presetLabel, 'next')
    assert.equal(harness.state.meta[TRUSTED_AUTO_LAUNCH_STATE_KEY], undefined)

    await runCountdown(harness)
    assert.equal(harness.calls.launches.length, 1)
    assert.equal(harness.state.meta[TRUSTED_AUTO_LAUNCH_STATE_KEY].consumedNextPreset.presetId, 'preset_next')

    harness.autoLaunch.beginUnlockSession()
    await harness.autoLaunch.observeAutoImportStatus(cleanAutoImport())
    assert.equal(harness.lastStatus().statusCategory, 'countdown')
    assert.equal(harness.lastStatus().presetLabel, 'default')
})

test('nextPresetId cancel and blocked launch-now attempts do not consume the one-time target', async () => {
    const metadata = metadataFixture()
    const canceled = createHarness({
        setting: {
            localDesktopOverridePresetId: null,
            acceptValidatedSelectionMetadata: true
        },
        workspace: baseWorkspace({ [WORKSPACE_SAFE_PRESET_METADATA_KEY]: metadata }),
        snapshot: baseSnapshot({
            presets: [basePreset('preset_next'), basePreset('preset_default')]
        })
    })
    await canceled.unlockAndClean()
    assert.equal(canceled.lastStatus().presetLabel, 'next')
    canceled.autoLaunch.cancelCurrentAttempt()
    assert.equal(canceled.state.meta[TRUSTED_AUTO_LAUNCH_STATE_KEY], undefined)

    const canceledRetry = await canceled.autoLaunch.launchNow()
    assert.equal(canceledRetry.success, true)
    assert.equal(canceled.calls.launches.length, 1)
    assert.equal(canceled.state.meta[TRUSTED_AUTO_LAUNCH_STATE_KEY].consumedNextPreset.presetId, 'preset_next')

    const blocked = createHarness({
        setting: {
            localDesktopOverridePresetId: null,
            acceptValidatedSelectionMetadata: true
        },
        workspace: baseWorkspace({ [WORKSPACE_SAFE_PRESET_METADATA_KEY]: metadata }),
        snapshot: baseSnapshot({
            presets: [basePreset('preset_next'), basePreset('preset_default')]
        })
    })
    await blocked.unlockAndClean()
    blocked.state.healthStatus = 'broken'
    const blockedResult = await blocked.autoLaunch.launchNow()
    assert.equal(blockedResult.success, false)
    assertBlocked(blocked, 'workspace-health-blocked')
    assert.equal(blocked.state.meta[TRUSTED_AUTO_LAUNCH_STATE_KEY], undefined)

    blocked.state.healthStatus = 'ready'
    const blockedRetry = await blocked.autoLaunch.launchNow()
    assert.equal(blockedRetry.success, true)
    assert.equal(blocked.lastStatus().presetLabel, 'next')
    assert.equal(blocked.state.meta[TRUSTED_AUTO_LAUNCH_STATE_KEY].consumedNextPreset.presetId, 'preset_next')
})

test('defaultPresetId is fallback only when validated selection metadata is explicitly accepted', async () => {
    const metadata = metadataFixture({ nextPresetId: null })
    const accepted = createHarness({
        setting: {
            localDesktopOverridePresetId: null,
            acceptValidatedSelectionMetadata: true
        },
        workspace: baseWorkspace({ [WORKSPACE_SAFE_PRESET_METADATA_KEY]: metadata }),
        snapshot: baseSnapshot({ presets: [basePreset('preset_default')] })
    })
    await accepted.unlockAndClean()
    assert.equal(accepted.lastStatus().statusCategory, 'countdown')
    assert.equal(accepted.lastStatus().presetLabel, 'default')

    const refused = createHarness({
        setting: {
            localDesktopOverridePresetId: null,
            acceptValidatedSelectionMetadata: false
        },
        workspace: baseWorkspace({ [WORKSPACE_SAFE_PRESET_METADATA_KEY]: metadata }),
        snapshot: baseSnapshot({ presets: [basePreset('preset_default')] })
    })
    await refused.unlockAndClean()
    assertBlocked(refused, 'no-target')
})

test('no target refuses auto-launch', async () => {
    const harness = createHarness({
        setting: {
            localDesktopOverridePresetId: null,
            acceptValidatedSelectionMetadata: false
        }
    })
    await harness.unlockAndClean()
    assertBlocked(harness, 'no-target')
    assert.equal(harness.calls.launches.length, 0)
})

test('time-derived snapshot revision and timestamp changes do not stale unchanged auto-launch attempts', async () => {
    const buildVolatileSnapshot = () => {
        let sequence = 0
        return () => {
            sequence += 1
            return baseSnapshot({
                revisionId: `srev_phase30_${sequence}`,
                timestamp: 1770000000000 + sequence
            })
        }
    }

    const launchNow = createHarness({
        buildCurrentSanitizedSnapshot: buildVolatileSnapshot()
    })
    await launchNow.unlockAndClean()
    const launchNowResult = await launchNow.autoLaunch.launchNow()
    assert.equal(launchNowResult.success, true)
    assert.equal(launchNow.calls.launches.length, 1)
    assert.equal(JSON.stringify(launchNow.calls.statuses).includes('token-invalid'), false)

    const countdown = createHarness({
        buildCurrentSanitizedSnapshot: buildVolatileSnapshot()
    })
    await countdown.unlockAndClean()
    await runCountdown(countdown)
    assert.equal(countdown.calls.launches.length, 1)
    assert.equal(JSON.stringify(countdown.calls.statuses).includes('token-invalid'), false)
})

test('selected browser URL changes invalidate the countdown token without leaking URLs', async () => {
    const harness = createHarness()
    await harness.unlockAndClean()

    harness.state.workspace = baseWorkspace({
        webTabs: [{
            url: 'https://changed.example/',
            label: 'Changed',
            enabled: true
        }]
    })
    harness.state.snapshot = baseSnapshot({
        availableItems: [{
            id: 'item_tab',
            type: 'browser-tab',
            label: 'Changed',
            status: 'available',
            source: 'browser',
            url: 'https://changed.example/'
        }]
    })

    await harness.scheduler.runNext()
    assertBlocked(harness, 'token-invalid')
    assert.equal(harness.calls.launches.length, 0)
    for (const status of harness.calls.statuses) {
        assert.equal(trustedAutoLaunchStatusContainsForbiddenMaterial(status), false)
    }
})

test('capability launch record changes invalidate the countdown token without migration or repair', async () => {
    const record = createCapabilityRecord({
        type: 'host-exe',
        provenance: 'test',
        displayName: 'Host App',
        launch: {
            method: 'spawn',
            path: 'C:\\Program Files\\Host\\Host.exe'
        }
    })
    const workspace = baseWorkspace({
        webTabs: [],
        desktopApps: [{
            capabilityId: record.capabilityId,
            displayName: 'Host App',
            enabled: true
        }],
        [WORKSPACE_CAPABILITY_VAULT_KEY]: {
            version: 1,
            records: {
                [record.capabilityId]: record
            }
        }
    })
    const snapshot = baseSnapshot({
        presets: [basePreset('preset_local', 'item_app')],
        availableItems: [{
            id: 'item_app',
            type: 'desktop-app',
            label: 'Host App',
            status: 'available',
            source: 'desktop'
        }]
    })
    const harness = createHarness({ workspace, snapshot })
    await harness.unlockAndClean()

    harness.state.workspace[WORKSPACE_CAPABILITY_VAULT_KEY].records[record.capabilityId].launch.path =
        'C:\\Program Files\\Host\\Changed.exe'

    await harness.scheduler.runNext()
    assertBlocked(harness, 'token-invalid')
    assert.equal(harness.calls.launches.length, 0)
    assert.equal(harness.calls.metaWrites, 0)
    for (const status of harness.calls.statuses) {
        assert.equal(trustedAutoLaunchStatusContainsForbiddenMaterial(status), false)
    }
})

test('volatile prepared launch diagnostics do not stale token but prepared target path changes do', async () => {
    const record = createCapabilityRecord({
        type: 'host-exe',
        provenance: 'test',
        displayName: 'Host App',
        launch: {
            method: 'spawn',
            path: 'C:\\Program Files\\Host\\Host.exe'
        }
    })
    const workspace = baseWorkspace({
        webTabs: [],
        desktopApps: [{
            capabilityId: record.capabilityId,
            displayName: 'Host App',
            enabled: true
        }],
        [WORKSPACE_CAPABILITY_VAULT_KEY]: {
            version: 1,
            records: {
                [record.capabilityId]: record
            }
        }
    })
    const snapshot = baseSnapshot({
        presets: [basePreset('preset_local', 'item_app')],
        availableItems: [{
            id: 'item_app',
            type: 'desktop-app',
            label: 'Host App',
            status: 'available',
            source: 'desktop'
        }]
    })
    let sequence = 0
    const withPreparedHostPath = (pathRef) => createHarness({
        workspace,
        snapshot,
        prepareLaunchWorkspaceConfig: async ({ workspace: selectedWorkspace }) => {
            sequence += 1
            const prepared = clone(selectedWorkspace)
            prepared.desktopApps[0] = {
                ...prepared.desktopApps[0],
                id: Date.now() + sequence,
                path: pathRef.value,
                launchSourceType: 'host-exe',
                launchMethod: 'spawn',
                hostResolution: {
                    status: 'available',
                    resolvedAt: Date.now() + sequence
                }
            }
            return prepared
        }
    })

    const stablePath = { value: 'C:\\Program Files\\Host\\Host.exe' }
    const stableHarness = withPreparedHostPath(stablePath)
    await stableHarness.unlockAndClean()
    await runCountdown(stableHarness)
    assert.equal(stableHarness.calls.launches.length, 1)
    for (const status of stableHarness.calls.statuses) {
        assert.equal(trustedAutoLaunchStatusContainsForbiddenMaterial(status), false)
    }

    const changedPath = { value: 'C:\\Program Files\\Host\\Host.exe' }
    const changedHarness = withPreparedHostPath(changedPath)
    await changedHarness.unlockAndClean()
    changedPath.value = 'C:\\Program Files\\Host\\Changed.exe'
    await changedHarness.scheduler.runNext()
    assertBlocked(changedHarness, 'token-invalid')
    assert.equal(changedHarness.calls.launches.length, 0)
})

test('selected item order and membership changes invalidate the countdown token', async () => {
    const workspace = baseWorkspace({
        webTabs: [
            { url: 'https://one.example/', label: 'One', enabled: true },
            { url: 'https://two.example/', label: 'Two', enabled: true }
        ]
    })
    const snapshot = baseSnapshot({
        availableItems: [
            {
                id: 'item_tab',
                type: 'browser-tab',
                label: 'One',
                status: 'available',
                source: 'browser',
                url: 'https://one.example/'
            },
            {
                id: 'item_tab_two',
                type: 'browser-tab',
                label: 'Two',
                status: 'available',
                source: 'browser',
                url: 'https://two.example/'
            }
        ],
        presets: [{
            id: 'preset_local',
            name: 'Local',
            order: 0,
            enabled: true,
            itemRefs: [
                { id: 'pref_one', itemId: 'item_tab', order: 0, enabled: true, metadataOnly: true },
                { id: 'pref_two', itemId: 'item_tab_two', order: 1, enabled: true, metadataOnly: true }
            ]
        }]
    })
    const harness = createHarness({ workspace, snapshot })
    await harness.unlockAndClean()

    harness.state.snapshot.presets[0].itemRefs[0].order = 10
    harness.state.snapshot.presets[0].itemRefs[1].order = 0

    await harness.scheduler.runNext()
    assertBlocked(harness, 'token-invalid')
    assert.equal(harness.calls.launches.length, 0)
})

test('raw phone or cloud patch data is never used as launch input', async () => {
    const metadata = metadataFixture({
        defaultPresetId: 'preset_cloud',
        nextPresetId: null,
        presets: ['preset_cloud']
    })
    metadata.newBrowserItems = [{
        id: 'patch_item_cloud',
        type: 'browser-tab',
        source: 'phone-patch',
        url: 'https://safe.example/',
        label: 'Safe Cloud Tab',
        enabled: true,
        metadataOnly: true
    }]
    const snapshot = baseSnapshot({
        presets: [basePreset('preset_cloud', 'patch_item_cloud')],
        availableItems: [{
            id: 'patch_item_cloud',
            type: 'browser-tab',
            label: 'Safe Cloud Tab',
            status: 'available',
            source: 'browser',
            url: 'https://safe.example/'
        }]
    })
    const workspace = baseWorkspace({
        webTabs: [],
        rawCloudPatch: {
            browserTabs: [{ url: 'https://evil.example/?token=secret#frag' }]
        },
        [WORKSPACE_SAFE_PRESET_METADATA_KEY]: metadata
    })
    const harness = createHarness({
        setting: {
            localDesktopOverridePresetId: null,
            acceptValidatedSelectionMetadata: true
        },
        workspace,
        snapshot
    })
    await harness.unlockAndClean()
    await runCountdown(harness)
    assert.equal(harness.calls.launches.length, 1)
    assert.equal(harness.calls.launches[0].webTabs[0].url, 'https://safe.example/')
    assert.equal(JSON.stringify(harness.calls.launches).includes('evil.example'), false)
})

test('phone-created browser tabs must still normalize to accepted public URLs', async () => {
    const metadata = metadataFixture({
        defaultPresetId: 'preset_cloud',
        nextPresetId: null,
        presets: ['preset_cloud']
    })
    metadata.newBrowserItems = [{
        id: 'patch_item_cloud',
        type: 'browser-tab',
        source: 'phone-patch',
        url: 'http://localhost:3000/',
        label: 'Localhost',
        enabled: true,
        metadataOnly: true
    }]
    const harness = createHarness({
        setting: {
            localDesktopOverridePresetId: null,
            acceptValidatedSelectionMetadata: true
        },
        workspace: baseWorkspace({
            webTabs: [],
            [WORKSPACE_SAFE_PRESET_METADATA_KEY]: metadata
        }),
        snapshot: baseSnapshot({
            presets: [basePreset('preset_cloud', 'patch_item_cloud')],
            availableItems: [{
                id: 'patch_item_cloud',
                type: 'browser-tab',
                label: 'Localhost',
                status: 'available',
                source: 'browser',
                url: 'http://localhost:3000/'
            }]
        })
    })
    await harness.unlockAndClean()
    assert.equal(harness.lastStatus().statusCategory, 'blocked')
    assert.equal(harness.calls.launches.length, 0)
})

test('clean auto-import variants allow countdown and every failure class blocks', async () => {
    assert.equal(trustedAutoImportStatusIsClean(cleanAutoImport()), true)
    assert.equal(trustedAutoImportStatusIsClean(cleanAutoImport([{ status: 'applied', code: 'merged', reason: 'merged' }])), true)

    const clean = createHarness()
    await clean.unlockAndClean()
    assert.equal(clean.lastStatus().statusCategory, 'countdown')

    const failureClasses = [
        'conflict',
        'stale-base',
        'revoked-device',
        'invalid-signature',
        'invalid-key',
        'forbidden-material',
        'duplicate-patch',
        'schema-invalid',
        'untrusted-author',
        'unavailable-runtime',
        'locked',
        'rejected'
    ]
    for (const category of failureClasses) {
        const harness = createHarness()
        harness.autoLaunch.beginUnlockSession()
        await harness.autoLaunch.observeAutoImportStatus(failedAutoImport(category))
        assert.equal(harness.lastStatus().statusCategory, 'blocked', category)
        assert.equal(harness.calls.launches.length, 0, category)
    }
})

test('already-decided merged is clean while other already-decided reasons block', async () => {
    const merged = createHarness()
    await merged.unlockAndClean(cleanAutoImport([{
        status: 'skipped',
        code: 'already-decided',
        reason: 'merged',
        metadataOnly: true
    }]))
    assert.equal(merged.lastStatus().statusCategory, 'countdown')

    for (const reason of ['conflict', 'skipped', 'invalid-patch']) {
        const harness = createHarness()
        harness.autoLaunch.beginUnlockSession()
        await harness.autoLaunch.observeAutoImportStatus({
            ...cleanAutoImport(),
            statusCategory: 'skipped',
            records: [{
                status: 'skipped',
                code: 'already-decided',
                reason,
                metadataOnly: true
            }]
        })
        assert.equal(harness.lastStatus().statusCategory, 'blocked', reason)
    }
})

test('revoked or untrusted author after prior merge blocks selected merged metadata', async () => {
    const metadata = metadataFixture({ nextPresetId: null })
    const harness = createHarness({
        authorTrusted: false,
        setting: {
            localDesktopOverridePresetId: null,
            acceptValidatedSelectionMetadata: true
        },
        workspace: baseWorkspace({ [WORKSPACE_SAFE_PRESET_METADATA_KEY]: metadata }),
        snapshot: baseSnapshot({ presets: [basePreset('preset_default')] })
    })
    await harness.unlockAndClean()
    assertBlocked(harness, 'author-not-trusted')
    assert.equal(harness.calls.authorChecks, 1)
})

test('metadata-selected presets require valid merged patch revision before launch', async () => {
    for (const patchRevisionId of [null, '', 'patch_phase30_wrong', 'patchrev bad', 42]) {
        const metadata = metadataFixture({ nextPresetId: null })
        metadata.lastMergedPatchRevisionId = patchRevisionId
        const harness = createHarness({
            setting: {
                localDesktopOverridePresetId: null,
                acceptValidatedSelectionMetadata: true
            },
            workspace: baseWorkspace({ [WORKSPACE_SAFE_PRESET_METADATA_KEY]: metadata }),
            snapshot: baseSnapshot({ presets: [basePreset('preset_default')] })
        })
        await harness.unlockAndClean()
        assertBlocked(harness, 'invalid-safe-metadata')
        assert.equal(harness.calls.authorChecks, 0)
        assert.equal(harness.calls.launches.length, 0)
    }

    const trusted = createHarness({
        setting: {
            localDesktopOverridePresetId: null,
            acceptValidatedSelectionMetadata: true
        },
        workspace: baseWorkspace({ [WORKSPACE_SAFE_PRESET_METADATA_KEY]: metadataFixture({ nextPresetId: null }) }),
        snapshot: baseSnapshot({ presets: [basePreset('preset_default')] })
    })
    await trusted.unlockAndClean()
    assert.equal(trusted.lastStatus().statusCategory, 'countdown')
    assert.equal(trusted.calls.authorChecks, 1)
})

test('local override ignores unrelated invalid metadata but blocks selected invalid metadata presets', async () => {
    const unrelatedMetadata = metadataFixture({ nextPresetId: null })
    unrelatedMetadata.lastMergedPatchRevisionId = ''
    const local = createHarness({
        setting: {
            localDesktopOverridePresetId: 'preset_local',
            acceptValidatedSelectionMetadata: true
        },
        workspace: baseWorkspace({ [WORKSPACE_SAFE_PRESET_METADATA_KEY]: unrelatedMetadata }),
        snapshot: baseSnapshot({
            presets: [basePreset('preset_local'), basePreset('preset_default')]
        })
    })
    await local.unlockAndClean()
    assert.equal(local.lastStatus().statusCategory, 'countdown')
    assert.equal(local.lastStatus().presetLabel, 'local')
    assert.equal(local.calls.authorChecks, 0)

    const selectedMetadata = metadataFixture({ nextPresetId: null })
    selectedMetadata.lastMergedPatchRevisionId = ''
    const selected = createHarness({
        setting: {
            localDesktopOverridePresetId: 'preset_default',
            acceptValidatedSelectionMetadata: false
        },
        workspace: baseWorkspace({ [WORKSPACE_SAFE_PRESET_METADATA_KEY]: selectedMetadata }),
        snapshot: baseSnapshot({ presets: [basePreset('preset_default')] })
    })
    await selected.unlockAndClean()
    assertBlocked(selected, 'invalid-safe-metadata')
    assert.equal(selected.calls.launches.length, 0)
})

test('merged metadata author invalid-key or stale-key failures block auto-launch', async () => {
    for (const reason of ['invalid-key', 'stale-key']) {
        const metadata = metadataFixture({ nextPresetId: null })
        const harness = createHarness({
            authorTrustResult: { trusted: false, reason, metadataOnly: true },
            setting: {
                localDesktopOverridePresetId: null,
                acceptValidatedSelectionMetadata: true
            },
            workspace: baseWorkspace({ [WORKSPACE_SAFE_PRESET_METADATA_KEY]: metadata }),
            snapshot: baseSnapshot({ presets: [basePreset('preset_default')] })
        })
        await harness.unlockAndClean()
        assertBlocked(harness, 'author-not-trusted')
        assert.equal(harness.calls.authorChecks, 1)
        assert.equal(harness.calls.launches.length, 0)
    }
})

test('missing, stale, and disabled presets block', async () => {
    const missing = createHarness({
        setting: { localDesktopOverridePresetId: 'preset_missing' }
    })
    await missing.unlockAndClean()
    assertBlocked(missing, 'missing-preset')

    const disabled = createHarness({
        snapshot: baseSnapshot({
            presets: [{ ...basePreset('preset_local'), enabled: false }]
        })
    })
    await disabled.unlockAndClean()
    assertBlocked(disabled, 'disabled-preset')

    const stale = createHarness({
        snapshot: baseSnapshot({
            availableItems: [{
                id: 'item_tab',
                type: 'browser-tab',
                label: 'Docs',
                status: 'disabled',
                source: 'browser',
                url: 'https://example.com/'
            }]
        })
    })
    await stale.unlockAndClean()
    assertBlocked(stale, 'stale-preset')
})

test('workspace health blocks needs-attention, broken, locked, and unavailable', async () => {
    for (const healthStatus of ['needs-attention', 'broken', 'locked', 'unavailable']) {
        const harness = createHarness({ healthStatus })
        await harness.unlockAndClean()
        assertBlocked(harness, 'workspace-health-blocked')
    }
})

test('missing stale capability blocks without migration or repair', async () => {
    const workspace = baseWorkspace({
        webTabs: [],
        desktopApps: [{
            capabilityId: `cap_${'ab'.repeat(32)}`,
            displayName: 'Missing App',
            enabled: true
        }],
        [WORKSPACE_CAPABILITY_VAULT_KEY]: { version: 1, records: {} }
    })
    const snapshot = baseSnapshot({
        presets: [basePreset('preset_local', 'item_app')],
        availableItems: [{
            id: 'item_app',
            type: 'desktop-app',
            label: 'Missing App',
            status: 'available',
            source: 'desktop'
        }]
    })
    const harness = createHarness({ workspace, snapshot })
    await harness.unlockAndClean()
    assertBlocked(harness, 'missing-capability')
    assert.equal(harness.calls.metaWrites, 0)
    assert.equal(harness.calls.prepared.length, 0)
})

test('missing browser profile blocks tab auto-launch', async () => {
    const harness = createHarness({ browserReady: false })
    await harness.unlockAndClean()
    assertBlocked(harness, 'missing-browser-profile')
})

test('account and profile non-ready states block', async () => {
    const account = createHarness({
        snapshot: baseSnapshot({
            availableItems: [
                {
                    id: 'item_tab',
                    type: 'browser-tab',
                    label: 'Docs',
                    status: 'available',
                    source: 'browser',
                    url: 'https://example.com/'
                },
                {
                    id: 'accti_google',
                    type: 'account-intention',
                    label: 'Google',
                    status: 'available',
                    source: 'account',
                    provider: 'google',
                    state: 'needs-auth',
                    metadataOnly: true
                }
            ],
            presets: [{
                ...basePreset('preset_local'),
                itemRefs: [{
                    ...basePreset('preset_local').itemRefs[0],
                    accountIntentionId: 'accti_google'
                }]
            }]
        })
    })
    await account.unlockAndClean()
    assertBlocked(account, 'account-not-ready')

    const profile = createHarness({
        snapshot: baseSnapshot({
            availableItems: [
                {
                    id: 'item_tab',
                    type: 'browser-tab',
                    label: 'Docs',
                    status: 'available',
                    source: 'browser',
                    url: 'https://example.com/'
                },
                {
                    id: 'profi_work',
                    type: 'profile-intention',
                    label: 'Work',
                    status: 'broken',
                    source: 'profile',
                    provider: 'google',
                    metadataOnly: true
                }
            ],
            presets: [{
                ...basePreset('preset_local'),
                itemRefs: [{
                    ...basePreset('preset_local').itemRefs[0],
                    profileIntentionId: 'profi_work'
                }]
            }]
        })
    })
    await profile.unlockAndClean()
    assertBlocked(profile, 'profile-not-ready')
})

test('host app availability failures block before launch', async () => {
    const record = createCapabilityRecord({
        type: 'host-exe',
        provenance: 'test',
        displayName: 'Host App',
        launch: {
            method: 'spawn',
            path: 'C:\\Program Files\\Host\\Host.exe'
        }
    })
    const workspace = baseWorkspace({
        webTabs: [],
        desktopApps: [{
            capabilityId: record.capabilityId,
            displayName: 'Host App',
            enabled: true
        }],
        [WORKSPACE_CAPABILITY_VAULT_KEY]: {
            version: 1,
            records: {
                [record.capabilityId]: record
            }
        }
    })
    const snapshot = baseSnapshot({
        presets: [basePreset('preset_local', 'item_app')],
        availableItems: [{
            id: 'item_app',
            type: 'desktop-app',
            label: 'Host App',
            status: 'available',
            source: 'desktop'
        }]
    })
    const harness = createHarness({ workspace, snapshot, hostUnavailable: true })
    await harness.unlockAndClean()
    assertBlocked(harness, 'host-unavailable')
    assert.equal(harness.calls.launches.length, 0)
})

test('cancel, disable, lock, manual, session capture, setting, target, workspace, and auto-import changes invalidate token', async () => {
    const cancel = createHarness()
    await cancel.unlockAndClean()
    cancel.autoLaunch.cancelCurrentAttempt()
    await runCountdown(cancel)
    assert.equal(cancel.calls.launches.length, 0)

    const disable = createHarness()
    await disable.unlockAndClean()
    disable.autoLaunch.disableAutoLaunch()
    await runCountdown(disable)
    assert.equal(disable.state.meta[TRUSTED_AUTO_LAUNCH_SETTINGS_KEY].enabled, false)
    assert.equal(disable.calls.launches.length, 0)

    const locked = createHarness()
    await locked.unlockAndClean()
    locked.autoLaunch.markLocked()
    await runCountdown(locked)
    assert.equal(locked.calls.launches.length, 0)

    const manual = createHarness()
    await manual.unlockAndClean()
    manual.autoLaunch.invalidate('manual-launch-request')
    await runCountdown(manual)
    assert.equal(manual.calls.launches.length, 0)

    const captureSession = createHarness()
    await captureSession.unlockAndClean()
    captureSession.autoLaunch.invalidate('session-capture')
    await runCountdown(captureSession)
    assert.equal(captureSession.calls.launches.length, 0)

    const saveCurrentSession = createHarness()
    await saveCurrentSession.unlockAndClean()
    saveCurrentSession.autoLaunch.invalidate('save-current-session')
    await runCountdown(saveCurrentSession)
    assert.equal(saveCurrentSession.calls.launches.length, 0)

    const setting = createHarness()
    await setting.unlockAndClean()
    setting.autoLaunch.updateSetting({ enabled: false })
    await runCountdown(setting)
    assert.equal(setting.calls.launches.length, 0)

    const workspace = createHarness()
    await workspace.unlockAndClean()
    workspace.state.snapshot = baseSnapshot({
        availableItems: [{
            id: 'item_tab',
            type: 'browser-tab',
            label: 'Docs',
            status: 'available',
            source: 'browser',
            state: 'workspace-changed',
            url: 'https://example.com/'
        }]
    })
    await workspace.scheduler.runNext()
    assertBlocked(workspace, 'token-invalid')
    assert.equal(workspace.calls.launches.length, 0)

    const autoImport = createHarness()
    await autoImport.unlockAndClean()
    await autoImport.autoLaunch.observeAutoImportStatus(cleanAutoImport())
    await runCountdown(autoImport)
    assert.equal(autoImport.calls.launches.length, 0)
})

test('active launch blocks auto-launch and launch-now rechecks gates', async () => {
    const active = createHarness({ launchActive: true })
    await active.unlockAndClean()
    assertBlocked(active, 'active-launch')

    const launchNow = createHarness()
    await launchNow.unlockAndClean()
    launchNow.state.healthStatus = 'broken'
    const result = await launchNow.autoLaunch.launchNow()
    assert.equal(result.success, false)
    assertBlocked(launchNow, 'workspace-health-blocked')
    assert.equal(launchNow.calls.launches.length, 0)
})

test('failed, blocked, or canceled auto-launch does not retry in same unlock without explicit launch now', async () => {
    const harness = createHarness({ healthStatus: 'broken' })
    await harness.unlockAndClean()
    assertBlocked(harness, 'workspace-health-blocked')
    harness.state.healthStatus = 'ready'
    await harness.autoLaunch.observeAutoImportStatus(cleanAutoImport())
    assert.equal(harness.calls.launches.length, 0)

    const retry = await harness.autoLaunch.launchNow()
    assert.equal(retry.success, true)
    assert.equal(harness.calls.launches.length, 1)
})

test('trusted auto-launch is once per unlock session and can run after a new unlock', async () => {
    const harness = createHarness()
    await harness.unlockAndClean()
    await harness.autoLaunch.launchNow()
    assert.equal(harness.calls.launches.length, 1)
    await harness.autoLaunch.observeAutoImportStatus(cleanAutoImport())
    assert.equal(harness.calls.launches.length, 1)

    harness.autoLaunch.beginUnlockSession()
    await harness.autoLaunch.observeAutoImportStatus(cleanAutoImport())
    await harness.autoLaunch.launchNow()
    assert.equal(harness.calls.launches.length, 2)
})

test('sanitized auto-launch status contains no forbidden renderer material', async () => {
    const harness = createHarness({
        setting: {
            localDesktopOverridePresetId: 'preset_local',
            acceptValidatedSelectionMetadata: true
        },
        snapshot: baseSnapshot({
            presets: [{
                ...basePreset('preset_local'),
                name: 'Open https://secret.example/?token=abc#frag from C:\\Users\\me'
            }]
        })
    })
    await harness.unlockAndClean()
    for (const status of harness.calls.statuses) {
        assert.equal(trustedAutoLaunchStatusContainsForbiddenMaterial(status), false)
    }
    assert.equal(harness.lastStatus().presetLabel.includes('https://'), false)
    assert.equal(harness.lastStatus().presetLabel.includes('?'), false)
    assert.equal(harness.lastStatus().presetLabel.includes('C:\\'), false)
})
