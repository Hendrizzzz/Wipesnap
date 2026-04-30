import { contextBridge, ipcRenderer } from 'electron'
import { validateCloudSyncInvocationPayload } from './cloudSyncPreloadValidation.js'
import { validateTrustedAutoLaunchSettingPayload } from './autoLaunchPreloadValidation.js'

function invokeCloudSync(channel, data) {
    return ipcRenderer.invoke(channel, validateCloudSyncInvocationPayload(data))
}

const wipesnapApi = {
    // Drive & Environment
    getDriveInfo: () => ipcRenderer.invoke('get-drive-info'),

    // Vault Operations
    vaultExists: () => ipcRenderer.invoke('vault-exists'),
    loadVaultMeta: () => ipcRenderer.invoke('load-vault-meta'),
    loadDiagnosticsSummary: () => ipcRenderer.invoke('load-diagnostics-summary'),
    loadWorkspaceHealth: () => ipcRenderer.invoke('load-workspace-health'),
    loadAccountSlots: () => ipcRenderer.invoke('load-account-slots'),
    createAccountSlot: (data) => ipcRenderer.invoke('create-account-slot', data),
    updateAccountSlot: (data) => ipcRenderer.invoke('update-account-slot', data),
    deleteAccountSlot: (data) => ipcRenderer.invoke('delete-account-slot', data),
    saveVault: (data) => ipcRenderer.invoke('save-vault', data),
    saveWorkspace: (workspace) => ipcRenderer.invoke('save-workspace', workspace),
    beginFactoryReset: () => ipcRenderer.invoke('begin-factory-reset'),
    factoryReset: (data) => ipcRenderer.invoke('factory-reset', data),

    // Security Modular Updates
    updatePin: (pin, freshPin) => ipcRenderer.invoke('update-pin', { pin, freshPin }),
    updateFastBoot: (enable, freshPin) => ipcRenderer.invoke('update-fastboot', { enable, freshPin }),
    updateClearCache: (enable) => ipcRenderer.invoke('update-clear-cache', enable),

    // Unlock
    unlockWithPin: (pin) => ipcRenderer.invoke('unlock-with-pin', pin),
    unlockWithPassword: (pw) => ipcRenderer.invoke('unlock-with-password', pw),
    tryFastBoot: () => ipcRenderer.invoke('try-fast-boot'),

    // File Browser
    browseExe: () => ipcRenderer.invoke('browse-exe'),
    browseFolder: () => ipcRenderer.invoke('browse-folder'),

    // App Import
    scanApps: () => ipcRenderer.invoke('scan-apps'),
    importApp: (data) => ipcRenderer.invoke('import-app', data),
    scanHostInstalledApps: () => ipcRenderer.invoke('scan-host-installed-apps'),
    scanStaleAppData: () => ipcRenderer.invoke('scan-stale-appdata'),
    cleanupStaleAppData: (data) => ipcRenderer.invoke('cleanup-stale-appdata', data),
    notifyImportStarted: () => ipcRenderer.send('import-started'),
    notifyImportFinished: () => ipcRenderer.send('import-finished'),
    onImportProgress: (callback) => {
        const listener = (_, data) => callback(data)
        ipcRenderer.on('import-progress', listener)
        return () => ipcRenderer.removeListener('import-progress', listener)
    },

    // Session Setup & Capture
    startSessionSetup: () => ipcRenderer.invoke('start-session-setup'),
    startSessionEdit: () => ipcRenderer.invoke('start-session-edit'),
    hasActiveBrowserSession: () => ipcRenderer.invoke('has-active-browser-session'),
    captureSession: (data) => ipcRenderer.invoke('capture-session', data),

    // Live Session Management
    saveCurrentSession: () => ipcRenderer.invoke('save-current-session'),
    quitAndRelaunch: (opts) => ipcRenderer.invoke('quit-and-relaunch', opts),
    closeDesktopApps: () => ipcRenderer.invoke('close-desktop-apps'),

    // Cloud Sync
    cloudSync: {
        uploadSanitizedSnapshot: (data) => invokeCloudSync('cloud-sync:upload-sanitized-snapshot', data),
        downloadEncryptedPatchSummaries: (data) => invokeCloudSync('cloud-sync:download-encrypted-patch-summaries', data),
        planSafePresetPatches: (data) => invokeCloudSync('cloud-sync:plan-safe-preset-patches', data),
        applyTrustedPatches: (data) => invokeCloudSync('cloud-sync:apply-trusted-patches', data),
        getAutoImportStatus: () => ipcRenderer.invoke('cloud-sync:get-auto-import-status'),
        onAutoImportStatus: (callback) => {
            const listener = (_, data) => callback(data)
            ipcRenderer.on('cloud-sync:auto-import-status', listener)
            return () => ipcRenderer.removeListener('cloud-sync:auto-import-status', listener)
        }
    },

    // Trusted Auto-Launch
    autoLaunch: {
        getStatus: () => ipcRenderer.invoke('auto-launch:get-status'),
        cancelCurrentAttempt: () => ipcRenderer.invoke('auto-launch:cancel-current-attempt'),
        disable: () => ipcRenderer.invoke('auto-launch:disable'),
        updateSetting: (data) => ipcRenderer.invoke(
            'auto-launch:update-setting',
            validateTrustedAutoLaunchSettingPayload(data)
        ),
        launchNow: () => ipcRenderer.invoke('auto-launch:launch-now'),
        onStatus: (callback) => {
            const listener = (_, data) => callback(data)
            ipcRenderer.on('auto-launch:status', listener)
            return () => ipcRenderer.removeListener('auto-launch:status', listener)
        }
    },

    // Automation Engine
    launchWorkspace: (workspace) => ipcRenderer.invoke('launch-workspace', workspace),
    onLaunchStatus: (callback) => {
        const listener = (_, msg) => callback(msg)
        ipcRenderer.on('launch-status', listener)
        return () => ipcRenderer.removeListener('launch-status', listener)
    },
    // Phase 16: Async launch completion event (non-blocking IPC)
    onLaunchComplete: (callback) => {
        const listener = (_, data) => callback(data)
        ipcRenderer.on('launch-complete', listener)
        return () => ipcRenderer.removeListener('launch-complete', listener)
    },
    onBrowserDisconnect: (callback) => {
        const listener = () => callback()
        ipcRenderer.on('browser-disconnected', listener)
        return () => ipcRenderer.removeListener('browser-disconnected', listener)
    },

    // Window Controls
    minimize: () => ipcRenderer.invoke('minimize-window'),
    close: () => ipcRenderer.invoke('close-window')
}

contextBridge.exposeInMainWorld('wipesnap', wipesnapApi)
// Compatibility alias for older renderer bundles and any saved automation snippets.
contextBridge.exposeInMainWorld('omnilaunch', wipesnapApi)
