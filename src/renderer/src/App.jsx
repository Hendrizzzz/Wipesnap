import { useState, useEffect } from 'react'
import UnlockScreen from './components/UnlockScreen'
import SetupScreen from './components/SetupScreen'
import DashboardScreen from './components/DashboardScreen'
import LaunchingScreen from './components/LaunchingScreen'
import { autoLaunchFlagForDashboardSave } from './rendererAutoLaunchPolicy'

export default function App() {
    const [screen, setScreen] = useState('loading')
    const [previousScreen, setPreviousScreen] = useState(null)
    const [driveInfo, setDriveInfo] = useState(null)
    const [workspace, setWorkspace] = useState(null)
    const [vaultMeta, setVaultMeta] = useState(null)
    const [error, setError] = useState(null)
    const [autoLaunch, setAutoLaunch] = useState(false)

    useEffect(() => {
        async function boot() {
            try {
                const info = await window.wipesnap.getDriveInfo()
                setDriveInfo(info)

                const exists = await window.wipesnap.vaultExists()
                if (!exists) {
                    setScreen('setup')
                    return
                }

                const meta = await window.wipesnap.loadVaultMeta()
                setVaultMeta(meta)

                if (meta?.fastBoot) {
                    const result = await window.wipesnap.tryFastBoot()
                    if (result.success) {
                        setWorkspace(result.workspace)
                        setAutoLaunch(false)
                        setScreen('launching')
                        return
                    }
                }

                setScreen('unlock')
            } catch (e) {
                setError(e.message)
                setScreen('unlock')
            }
        }
        boot()
    }, [])

    const handleSetupComplete = () => {
        setScreen('loading')
        setTimeout(async () => {
            const exists = await window.wipesnap.vaultExists()
            if (exists) {
                const meta = await window.wipesnap.loadVaultMeta()
                setVaultMeta(meta)
                setScreen('unlock')
            }
        }, 100)
    }

    const handleUnlock = async (workspace, mp) => {
        setWorkspace(workspace)
        setAutoLaunch(false)
        setScreen('launching')
    }

    // Settings from launching screen  
    const handleSettingsFromLaunch = () => {
        setPreviousScreen('launching')
        setScreen('dashboard')
    }

    // When dashboard saves or closes, return to where we came from
    const handleDashboardSave = (forceRelaunch = false, newWorkspace = null) => {
        if (newWorkspace) {
            setWorkspace(newWorkspace)
        }

        if (forceRelaunch) {
            setAutoLaunch(autoLaunchFlagForDashboardSave({ forceRelaunch }))
            setScreen('launching')
            setPreviousScreen(null)
            return
        }

        if (previousScreen === 'launching') {
            // Return directly to launching — keep current session alive
            setAutoLaunch(false)
            setScreen('launching')
            setPreviousScreen(null)
        } else {
            // Came from unlock — need to re-enter password flow
            setScreen('loading')
            setTimeout(async () => {
                const meta = await window.wipesnap.loadVaultMeta()
                setVaultMeta(meta)
                setScreen('unlock')
            }, 100)
            setPreviousScreen(null)
        }
    }

    const handleDashboardCancel = () => {
        if (previousScreen === 'launching') {
            // Return to launching, do not restart current session
            setAutoLaunch(false)
            setScreen('launching')
        } else {
            setScreen('unlock')
        }
        setPreviousScreen(null)
    }

    return (
        <div className="w-full h-full bg-[#1a1a24] relative overflow-hidden flex flex-col">
            {/* Titlebar */}
            <div className="titlebar">
                <button
                    onClick={() => window.wipesnap.minimize()}
                    className="btn-icon"
                    style={{ width: 28, height: 28 }}
                    title="Minimize"
                >
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M1 5h8" />
                    </svg>
                </button>
                <button
                    onClick={() => window.wipesnap.close()}
                    className="btn-icon"
                    style={{ width: 28, height: 28 }}
                    title="Close"
                >
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M1 1l8 8M9 1l-8 8" />
                    </svg>
                </button>
            </div>

            {/* Main Content */}
            <div className="flex-1 flex items-center justify-center px-6 pb-6">
                {screen === 'loading' && (
                    <div className="flex flex-col items-center gap-3 animate-fade-in">
                        <div className="spinner" />
                        <p className="text-secondary text-sm">Loading...</p>
                    </div>
                )}

                {screen === 'setup' && (
                    <SetupScreen driveInfo={driveInfo} onComplete={handleSetupComplete} />
                )}

                {screen === 'unlock' && (
                    <UnlockScreen
                        driveInfo={driveInfo}
                        vaultMeta={vaultMeta}
                        onUnlock={handleUnlock}
                    />
                )}

                {screen === 'dashboard' && (
                    <DashboardScreen
                        driveInfo={driveInfo}
                        workspace={workspace}
                        vaultMeta={vaultMeta}
                        onSave={handleDashboardSave}
                        onCancel={handleDashboardCancel}
                    />
                )}

                {screen === 'launching' && (
                    <LaunchingScreen
                        workspace={workspace}
                        autoLaunch={autoLaunch}
                        onSettingsClick={handleSettingsFromLaunch}
                    />
                )}
            </div>
        </div>
    )
}
