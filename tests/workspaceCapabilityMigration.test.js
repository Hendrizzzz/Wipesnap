import assert from 'assert/strict'
import { test } from 'node:test'
import { createCapabilityRecord } from '../src/main/capabilityStore.js'
import {
    WORKSPACE_CAPABILITY_VAULT_KEY,
    createVaultLocalExecutableCapability,
    migrateWorkspaceLaunchCapabilities,
    migrationReportToMetadataSummary,
    prepareRendererWorkspaceSave,
    rehydrateWorkspaceLaunchCapabilities,
    sanitizeWorkspaceForRenderer,
    workspaceEntryHasRawLaunchAuthority
} from '../src/main/workspaceCapabilityMigration.js'
import { WORKSPACE_SAFE_PRESET_METADATA_KEY } from '../src/main/safePresetMetadata.js'

const FIXED_NOW = '2026-04-25T00:00:00.000Z'

function bytesSequence(...hexBytes) {
    let index = 0
    return (size) => {
        const value = hexBytes[index] ?? hexBytes[hexBytes.length - 1]
        index += 1
        return Buffer.alloc(size, value)
    }
}

function manifestResolver(manifestId) {
    const manifests = {
        Imported_App: {
            manifestId: 'Imported_App',
            safeName: 'Imported_App',
            displayName: 'Imported App',
            selectedExecutable: {
                relativePath: 'Imported.exe'
            }
        }
    }
    return manifests[manifestId] || null
}

test('verified browse, scan, and import-style legacy records migrate to opaque capability workspace rows', () => {
    const legacyBrowse = {
        id: 'legacy-browse-code',
        launchSourceType: 'host-exe',
        launchMethod: 'spawn',
        path: 'C:\\Program Files\\Microsoft VS Code\\Code.exe',
        provenance: 'browse-exe'
    }
    const legacyScan = {
        id: 'legacy-scan-registry',
        launchSourceType: 'registry-uninstall',
        launchMethod: 'spawn',
        path: 'C:\\Program Files\\Scanned\\Scanned.exe',
        registryKey: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Scanned',
        provenance: 'host-scan'
    }

    const migrated = migrateWorkspaceLaunchCapabilities({
        webTabs: [{ url: 'https://example.com', enabled: true }],
        desktopApps: [
            {
                id: 'browse-row',
                name: 'Visual Studio Code',
                path: legacyBrowse.path,
                launchSourceType: 'host-exe',
                launchMethod: 'spawn',
                launchCapabilityId: legacyBrowse.id,
                enabled: true
            },
            {
                id: 'scan-row',
                name: 'Scanned App',
                path: legacyScan.path,
                launchSourceType: 'registry-uninstall',
                launchMethod: 'spawn',
                registryKey: legacyScan.registryKey,
                launchCapabilityId: legacyScan.id,
                enabled: true
            },
            {
                id: 'import-row',
                name: 'Imported App',
                path: '[USB]\\Apps\\Imported_App\\Imported.exe',
                launchSourceType: 'vault-archive',
                launchMethod: 'spawn',
                manifestId: 'Imported_App',
                enabled: true
            }
        ]
    }, {
        legacyCapabilities: [legacyBrowse, legacyScan],
        manifestResolver,
        randomBytes: bytesSequence(0x01, 0x02, 0x03),
        now: FIXED_NOW
    })

    assert.equal(migrated.changed, true)
    assert.equal(migrated.migrationReport.verified, 3)
    assert.equal(migrated.migrationReport.quarantined, 0)

    const apps = migrated.workspace.desktopApps
    assert.deepEqual(apps.map(app => app.capabilityId), [
        `cap_${'01'.repeat(32)}`,
        `cap_${'02'.repeat(32)}`,
        `cap_${'03'.repeat(32)}`
    ])
    assert.equal(apps.every(app => !workspaceEntryHasRawLaunchAuthority(app)), true)
    assert.equal(apps.every(app => app.enabled), true)

    const records = migrated.workspace[WORKSPACE_CAPABILITY_VAULT_KEY].records
    assert.equal(records[`cap_${'01'.repeat(32)}`].type, 'host-exe')
    assert.equal(records[`cap_${'02'.repeat(32)}`].type, 'registry-uninstall')
    assert.equal(records[`cap_${'03'.repeat(32)}`].type, 'vault-archive')
    assert.equal(records[`cap_${'03'.repeat(32)}`].launch.storageId, 'Imported_App')

    const rehydrated = rehydrateWorkspaceLaunchCapabilities(migrated.workspace, {
        capabilityVault: migrated.capabilityVault,
        manifestResolver
    })
    assert.deepEqual(rehydrated.desktopApps.map(app => app.path), [
        'C:\\Program Files\\Microsoft VS Code\\Code.exe',
        'C:\\Program Files\\Scanned\\Scanned.exe',
        '[USB]\\Apps\\Imported_App\\Imported.exe'
    ])

    const summary = migrationReportToMetadataSummary(migrated.migrationReport)
    assert.deepEqual(Object.keys(summary), ['version', 'migratedAt', 'verified', 'quarantined', 'alreadyMigrated'])
})

test('arbitrary renderer host executable entry is quarantined without preserving raw launch fields', () => {
    const migrated = migrateWorkspaceLaunchCapabilities({
        desktopApps: [{
            id: 'forged-row',
            name: 'Forged Notepad',
            path: 'C:\\Windows\\System32\\notepad.exe',
            launchSourceType: 'host-exe',
            launchMethod: 'spawn',
            enabled: true
        }]
    }, {
        now: FIXED_NOW
    })

    const [app] = migrated.workspace.desktopApps
    assert.equal(app.enabled, false)
    assert.equal(app.quarantined, true)
    assert.match(app.quarantineReason, /No main-issued legacy capability evidence/)
    assert.equal(workspaceEntryHasRawLaunchAuthority(app), false)
    assert.deepEqual(Object.keys(migrated.workspace[WORKSPACE_CAPABILITY_VAULT_KEY].records), [])

    const rehydrated = rehydrateWorkspaceLaunchCapabilities(migrated.workspace)
    assert.deepEqual(rehydrated.desktopApps, [])
})

test('renderer-supplied capability vault is ignored and cannot grant launch authority', () => {
    const forgedRecord = createCapabilityRecord({
        type: 'host-exe',
        provenance: 'browse-exe',
        displayName: 'Forged Notepad',
        launch: {
            path: 'C:\\Windows\\System32\\notepad.exe'
        },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: true,
            ownership: 'owned-process'
        }
    }, {
        randomBytes: bytesSequence(0xee),
        now: FIXED_NOW
    })
    const forgedVault = {
        version: 1,
        records: {
            [forgedRecord.capabilityId]: forgedRecord
        }
    }
    const rendererWorkspace = {
        desktopApps: [{
            name: 'Forged Notepad',
            capabilityId: forgedRecord.capabilityId,
            enabled: true
        }],
        [WORKSPACE_CAPABILITY_VAULT_KEY]: forgedVault
    }

    const migrated = migrateWorkspaceLaunchCapabilities(rendererWorkspace, {
        now: FIXED_NOW
    })

    const [app] = migrated.workspace.desktopApps
    assert.equal(app.enabled, false)
    assert.equal(app.quarantined, true)
    assert.equal(app.quarantineCode, 'missing-capability')
    assert.match(app.quarantineReason, /missing, stale, or unavailable/)
    assert.deepEqual(Object.keys(migrated.capabilityVault.records), [])
    assert.deepEqual(rehydrateWorkspaceLaunchCapabilities(migrated.workspace).desktopApps, [])

    const trusted = migrateWorkspaceLaunchCapabilities(rendererWorkspace, {
        existingCapabilityVault: forgedVault,
        now: FIXED_NOW
    })
    const rehydrated = rehydrateWorkspaceLaunchCapabilities(trusted.workspace, {
        capabilityVault: trusted.capabilityVault
    })
    assert.deepEqual(rehydrated.desktopApps.map(appConfig => appConfig.path), [
        'C:\\Windows\\System32\\notepad.exe'
    ])
})

test('protocol capability with mismatched scheme is quarantined', () => {
    const legacyProtocol = {
        id: 'legacy-protocol',
        launchSourceType: 'protocol-uri',
        launchMethod: 'protocol',
        path: 'ms-settings:',
        protocolScheme: 'zoommtg',
        provenance: 'host-scan'
    }

    const migrated = migrateWorkspaceLaunchCapabilities({
        desktopApps: [{
            name: 'Bad Protocol',
            path: 'ms-settings:',
            launchSourceType: 'protocol-uri',
            launchMethod: 'protocol',
            protocolScheme: 'zoommtg',
            launchCapabilityId: legacyProtocol.id
        }]
    }, {
        legacyCapabilities: [legacyProtocol],
        now: FIXED_NOW
    })

    const [app] = migrated.workspace.desktopApps
    assert.equal(app.quarantined, true)
    assert.equal(app.enabled, false)
    assert.match(app.quarantineReason, /protocolScheme must match/)
    assert.equal(workspaceEntryHasRawLaunchAuthority(app), false)
})

test('legacy Windows script host capabilities are quarantined during migration', () => {
    const legacyScript = {
        id: 'legacy-script',
        launchSourceType: 'host-exe',
        launchMethod: 'spawn',
        path: 'C:\\Scripts\\Launch.cmd',
        provenance: 'browse-exe'
    }

    const migrated = migrateWorkspaceLaunchCapabilities({
        desktopApps: [{
            id: 'script-row',
            name: 'Legacy Script',
            path: legacyScript.path,
            launchSourceType: 'host-exe',
            launchMethod: 'spawn',
            launchCapabilityId: legacyScript.id,
            enabled: true
        }]
    }, {
        legacyCapabilities: [legacyScript],
        now: FIXED_NOW
    })

    const [app] = migrated.workspace.desktopApps
    assert.equal(app.enabled, false)
    assert.equal(app.quarantined, true)
    assert.match(app.quarantineReason, /\.bat\/\.cmd script launch file/)
    assert.equal(workspaceEntryHasRawLaunchAuthority(app), false)
    assert.deepEqual(Object.keys(migrated.workspace[WORKSPACE_CAPABILITY_VAULT_KEY].records), [])
    assert.deepEqual(rehydrateWorkspaceLaunchCapabilities(migrated.workspace).desktopApps, [])
})

test('missing capability fails closed during launch rehydration', () => {
    assert.throws(() => rehydrateWorkspaceLaunchCapabilities({
        desktopApps: [{
            name: 'Missing Capability',
            capabilityId: `cap_${'aa'.repeat(32)}`,
            enabled: true
        }],
        [WORKSPACE_CAPABILITY_VAULT_KEY]: {
            version: 1,
            records: {}
        }
    }), /missing, stale, or unavailable/)
})

test('migrated workspace entries store only capability ids and limited UI state', () => {
    const legacyBrowse = {
        id: 'legacy-browse',
        launchSourceType: 'host-exe',
        launchMethod: 'spawn',
        path: 'C:\\Program Files\\Verified\\Verified.exe',
        provenance: 'browse-exe'
    }

    const migrated = migrateWorkspaceLaunchCapabilities({
        desktopApps: [{
            id: 'verified-row',
            name: 'Verified',
            path: legacyBrowse.path,
            args: '',
            launchSourceType: 'host-exe',
            launchMethod: 'spawn',
            launchCapabilityId: legacyBrowse.id,
            portableData: true,
            enabled: true
        }]
    }, {
        legacyCapabilities: [legacyBrowse],
        randomBytes: bytesSequence(0x0a),
        now: FIXED_NOW
    })

    const [app] = migrated.workspace.desktopApps
    assert.deepEqual(Object.keys(app).sort(), ['capabilityId', 'displayName', 'enabled', 'id'].sort())
    assert.equal(app.capabilityId, `cap_${'0a'.repeat(32)}`)
    assert.equal(workspaceEntryHasRawLaunchAuthority(app), false)
})

test('workspace capability migration preserves encrypted account slots but renderer saves cannot supply them', () => {
    const accountSlots = [{
        id: `acct_${'e5'.repeat(24)}`,
        provider: 'google',
        label: 'Personal',
        identifierHint: 'user@example.com',
        state: 'unknown',
        lastCheckedAt: 0,
        notes: ''
    }]

    const migrated = migrateWorkspaceLaunchCapabilities({
        webTabs: [],
        desktopApps: [],
        accountSlots
    }, {
        now: FIXED_NOW
    })

    assert.deepEqual(migrated.workspace.accountSlots, accountSlots)
    assert.equal(sanitizeWorkspaceForRenderer(migrated.workspace).accountSlots, undefined)

    assert.throws(() => prepareRendererWorkspaceSave({
        webTabs: [],
        desktopApps: [],
        accountSlots
    }), /accountSlots is main-owned/)

    assert.throws(() => prepareRendererWorkspaceSave({
        webTabs: [],
        desktopApps: [],
        [WORKSPACE_SAFE_PRESET_METADATA_KEY]: { version: 1 }
    }), /safePresetMetadata is main-owned/)
})

test('renderer-invented raw launch path cannot be saved or launched', () => {
    assert.throws(() => prepareRendererWorkspaceSave({
        desktopApps: [{
            id: 'forged-row',
            displayName: 'Forged Notepad',
            path: 'C:\\Windows\\System32\\notepad.exe',
            launchSourceType: 'host-exe',
            launchMethod: 'spawn',
            enabled: true
        }]
    }), /path is not accepted from renderer workspace data/)

    assert.throws(() => rehydrateWorkspaceLaunchCapabilities({
        desktopApps: [{
            displayName: 'Forged Notepad',
            path: 'C:\\Windows\\System32\\notepad.exe',
            launchSourceType: 'host-exe',
            launchMethod: 'spawn',
            enabled: true
        }]
    }), /missing a capabilityId/)
})

test('valid renderer capabilityId can be saved and rehydrated for launch', () => {
    const record = createCapabilityRecord({
        type: 'host-exe',
        provenance: 'browse-exe',
        displayName: 'Verified App',
        launch: {
            path: 'C:\\Program Files\\Verified\\Verified.exe'
        },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: true,
            ownership: 'owned-process'
        }
    }, {
        randomBytes: bytesSequence(0x44),
        now: FIXED_NOW
    })

    const saved = prepareRendererWorkspaceSave({
        webTabs: [{ url: 'https://example.com', enabled: true }],
        desktopApps: [{
            id: 'verified-row',
            capabilityId: record.capabilityId,
            displayName: 'Verified Renamed',
            enabled: true
        }]
    }, {
        pendingCapabilityRecords: [record]
    })

    const [storedApp] = saved.workspace.desktopApps
    assert.deepEqual(Object.keys(storedApp).sort(), ['capabilityId', 'displayName', 'enabled', 'id'].sort())
    assert.equal(storedApp.displayName, 'Verified Renamed')
    assert.deepEqual(saved.capabilityVault.records[record.capabilityId], record)

    const rendererWorkspace = sanitizeWorkspaceForRenderer(saved.workspace)
    assert.equal(WORKSPACE_CAPABILITY_VAULT_KEY in rendererWorkspace, false)
    assert.equal(rendererWorkspace.desktopApps[0].capabilityId, record.capabilityId)

    const launchWorkspace = rehydrateWorkspaceLaunchCapabilities(saved.workspace, {
        capabilityVault: saved.capabilityVault
    })
    assert.deepEqual(launchWorkspace.desktopApps.map(app => app.path), [
        'C:\\Program Files\\Verified\\Verified.exe'
    ])
    assert.equal(launchWorkspace.desktopApps[0].launchSourceType, 'host-exe')
    assert.equal(launchWorkspace.desktopApps[0].launchMethod, 'spawn')
})

test('host-exe renderer args reject by default at save time', () => {
    const record = createCapabilityRecord({
        type: 'host-exe',
        provenance: 'browse-exe',
        displayName: 'Verified App',
        launch: {
            path: 'C:\\Program Files\\Verified\\Verified.exe'
        },
        policy: {
            canCloseFromWipesnap: true,
            ownership: 'owned-process'
        }
    }, {
        randomBytes: bytesSequence(0x45),
        now: FIXED_NOW
    })

    assert.throws(() => prepareRendererWorkspaceSave({
        desktopApps: [{
            capabilityId: record.capabilityId,
            displayName: 'Verified App',
            enabled: true,
            userArgs: ['--profile=Work']
        }]
    }, {
        pendingCapabilityRecords: [record]
    }), /does not allow renderer-supplied launch arguments/)
})

test('protocol renderer args reject by default at save time', () => {
    const record = createCapabilityRecord({
        type: 'protocol-uri',
        provenance: 'protocol-scan',
        displayName: 'Meeting Protocol',
        launch: {
            method: 'protocol',
            uri: 'zoommtg:'
        },
        policy: {
            canCloseFromWipesnap: false,
            ownership: 'external'
        }
    }, {
        randomBytes: bytesSequence(0x46),
        now: FIXED_NOW
    })

    assert.throws(() => prepareRendererWorkspaceSave({
        desktopApps: [{
            capabilityId: record.capabilityId,
            displayName: 'Meeting Protocol',
            enabled: true,
            userArgs: ['--url=zoommtg://attend']
        }]
    }, {
        pendingCapabilityRecords: [record]
    }), /does not allow renderer-supplied launch arguments/)
})

test('packaged-app renderer args reject by default at save time', () => {
    const record = createCapabilityRecord({
        type: 'packaged-app',
        provenance: 'packaged-app-scan',
        displayName: 'Calculator',
        launch: {
            method: 'packaged-app',
            path: 'shell:AppsFolder\\Microsoft.WindowsCalculator_8wekyb3d8bbwe!App'
        },
        policy: {
            canCloseFromWipesnap: false,
            ownership: 'external'
        }
    }, {
        randomBytes: bytesSequence(0x49),
        now: FIXED_NOW
    })

    assert.throws(() => prepareRendererWorkspaceSave({
        desktopApps: [{
            capabilityId: record.capabilityId,
            displayName: 'Calculator',
            enabled: true,
            userArgs: ['--debug']
        }]
    }, {
        pendingCapabilityRecords: [record]
    }), /does not allow renderer-supplied launch arguments/)
})

test('imported app args follow explicit manifest allow policy at save and launch rehydration', () => {
    const manifest = {
        manifestId: 'Imported_App',
        safeName: 'Imported_App',
        displayName: 'Imported App',
        selectedExecutable: {
            relativePath: 'Imported.exe'
        },
        launchArgsPolicy: {
            allowedArgs: 'allowlist',
            allowedPrefixes: ['--profile', '--safe-mode'],
            maxArgs: 2,
            maxArgLength: 32
        }
    }
    const { record, appConfig } = createVaultLocalExecutableCapability({
        vaultRelativePath: 'Apps\\Imported_App\\Imported.exe',
        manifest,
        id: 'imported-args-row',
        randomBytes: bytesSequence(0x47),
        now: FIXED_NOW
    })

    assert.equal(record.policy.allowedArgs, 'allowlist')
    assert.deepEqual(record.policy.allowedPrefixes, ['--profile', '--safe-mode'])

    const saved = prepareRendererWorkspaceSave({
        desktopApps: [{
            id: appConfig.id,
            capabilityId: appConfig.capabilityId,
            displayName: appConfig.displayName,
            enabled: true,
            userArgs: ['--profile=Work', '--safe-mode']
        }]
    }, {
        pendingCapabilityRecords: [record]
    })

    assert.deepEqual(saved.workspace.desktopApps[0].userArgs, ['--profile=Work', '--safe-mode'])

    const launchWorkspace = rehydrateWorkspaceLaunchCapabilities(saved.workspace, {
        capabilityVault: saved.capabilityVault,
        manifestResolver: () => manifest
    })

    assert.deepEqual(launchWorkspace.desktopApps[0].args, ['--profile=Work', '--safe-mode'])
    assert.equal(launchWorkspace.desktopApps[0].path, '[USB]\\Apps\\Imported_App\\Imported.exe')

    assert.throws(() => prepareRendererWorkspaceSave({
        desktopApps: [{
            capabilityId: record.capabilityId,
            displayName: appConfig.displayName,
            enabled: true,
            userArgs: ['--debug']
        }]
    }, {
        pendingCapabilityRecords: [record]
    }), /outside its allowlist/)
})

test('invalid persisted user args fail closed during launch rehydration', () => {
    const record = createCapabilityRecord({
        type: 'host-exe',
        provenance: 'browse-exe',
        displayName: 'Verified App',
        launch: {
            path: 'C:\\Program Files\\Verified\\Verified.exe'
        },
        policy: {
            allowedArgs: 'allowlist',
            allowedPrefixes: ['--profile'],
            maxArgs: 1,
            maxArgLength: 24,
            canCloseFromWipesnap: true,
            ownership: 'owned-process'
        }
    }, {
        randomBytes: bytesSequence(0x48),
        now: FIXED_NOW
    })
    const capabilityVault = {
        version: 1,
        records: {
            [record.capabilityId]: record
        }
    }

    assert.throws(() => rehydrateWorkspaceLaunchCapabilities({
        desktopApps: [{
            capabilityId: record.capabilityId,
            displayName: 'Verified App',
            enabled: true,
            userArgs: ['--debug']
        }]
    }, {
        capabilityVault
    }), /outside its allowlist/)

    assert.throws(() => rehydrateWorkspaceLaunchCapabilities({
        desktopApps: [{
            capabilityId: record.capabilityId,
            displayName: 'Verified App',
            enabled: true,
            userArgs: ['--profile=Work', '--profile=Other']
        }]
    }, {
        capabilityVault
    }), /too many launch arguments/)

    assert.throws(() => rehydrateWorkspaceLaunchCapabilities({
        desktopApps: [{
            capabilityId: record.capabilityId,
            displayName: 'Verified App',
            enabled: true,
            userArgs: ['--profile=ThisValueIsTooLong']
        }]
    }, {
        capabilityVault
    }), /overlong launch argument/)
})

test('USB-local executable browse issues a manifest-backed capability that can be saved and launched', () => {
    const { record, appConfig } = createVaultLocalExecutableCapability({
        vaultRelativePath: 'Apps\\Imported_App\\Imported.exe',
        manifest: manifestResolver('Imported_App'),
        id: 'usb-local-row',
        randomBytes: bytesSequence(0x77),
        now: FIXED_NOW
    })

    assert.equal(record.capabilityId, `cap_${'77'.repeat(32)}`)
    assert.equal(record.type, 'vault-archive')
    assert.equal(record.provenance, 'import-manifest')
    assert.equal(record.launch.storageId, 'Imported_App')
    assert.equal(record.launch.manifestId, 'Imported_App')
    assert.equal(appConfig.capabilityId, record.capabilityId)
    assert.equal(appConfig.path, '[USB]\\Apps\\Imported_App\\Imported.exe')

    const saved = prepareRendererWorkspaceSave({
        desktopApps: [{
            id: appConfig.id,
            capabilityId: appConfig.capabilityId,
            displayName: appConfig.displayName,
            enabled: true
        }]
    }, {
        pendingCapabilityRecords: [record]
    })

    assert.equal(workspaceEntryHasRawLaunchAuthority(saved.workspace.desktopApps[0]), false)
    const launchWorkspace = rehydrateWorkspaceLaunchCapabilities(saved.workspace, {
        capabilityVault: saved.capabilityVault,
        manifestResolver
    })
    assert.equal(launchWorkspace.desktopApps[0].path, '[USB]\\Apps\\Imported_App\\Imported.exe')
    assert.equal(launchWorkspace.desktopApps[0].launchSourceType, 'vault-archive')
})

test('USB-local browse selections fail closed without matching manifest evidence', () => {
    assert.throws(() => createVaultLocalExecutableCapability({
        vaultRelativePath: 'Apps\\Imported_App\\Other.exe',
        manifest: manifestResolver('Imported_App'),
        randomBytes: bytesSequence(0x88),
        now: FIXED_NOW
    }), /executable does not match/)

    assert.throws(() => createVaultLocalExecutableCapability({
        vaultRelativePath: 'Apps\\Imported_App',
        manifest: manifestResolver('Imported_App'),
        randomBytes: bytesSequence(0x89),
        now: FIXED_NOW
    }), /Imported app path must use/)

    assert.throws(() => createVaultLocalExecutableCapability({
        vaultRelativePath: 'Apps\\Missing_App\\Missing.exe',
        manifest: null,
        randomBytes: bytesSequence(0x8a),
        now: FIXED_NOW
    }), /requires a verified imported app manifest/)

    assert.throws(() => createVaultLocalExecutableCapability({
        vaultRelativePath: 'Apps\\Imported_App\\Imported.exe',
        manifest: {
            ...manifestResolver('Imported_App'),
            launchArgsPolicy: 'allowlist'
        },
        randomBytes: bytesSequence(0x8b),
        now: FIXED_NOW
    }), /launchArgsPolicy must be an object/)
})

test('stale renderer capabilityId fails closed during save', () => {
    assert.throws(() => prepareRendererWorkspaceSave({
        desktopApps: [{
            capabilityId: `cap_${'55'.repeat(32)}`,
            displayName: 'Stale App',
            enabled: true
        }]
    }, {
        existingCapabilityVault: {
            version: 1,
            records: {}
        }
    }), /missing, stale, or unavailable/)
})

test('renderer raw metadata injection is rejected during save', () => {
    const record = createCapabilityRecord({
        type: 'host-exe',
        provenance: 'browse-exe',
        displayName: 'Verified App',
        launch: {
            path: 'C:\\Program Files\\Verified\\Verified.exe'
        }
    }, {
        randomBytes: bytesSequence(0x66),
        now: FIXED_NOW
    })

    assert.throws(() => prepareRendererWorkspaceSave({
        desktopApps: [{
            capabilityId: record.capabilityId,
            displayName: 'Injected App',
            enabled: true,
            registryKey: 'HKCU\\Software\\Injected',
            supportTier: 'verified',
            closePolicy: 'owned-tree'
        }]
    }, {
        pendingCapabilityRecords: [record]
    }), /registryKey is not accepted from renderer workspace data/)

    assert.throws(() => prepareRendererWorkspaceSave({
        desktopApps: [{
            capabilityId: record.capabilityId,
            displayName: 'Injected Vault App',
            enabled: true
        }],
        [WORKSPACE_CAPABILITY_VAULT_KEY]: {
            version: 1,
            records: {
                [record.capabilityId]: record
            }
        }
    }), /main-owned workspace metadata/)
})
