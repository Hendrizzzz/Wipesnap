import { useEffect, useMemo, useState } from 'react'
import { shouldAutoStartRendererLaunch } from '../rendererAutoLaunchPolicy'

function normalizeStatusMessage(message) {
    return String(message || '')
        .replace(/[â€”â€“]/g, '-')
        .replace(/\s+/g, ' ')
        .trim()
}

function parseScopedStatus(message) {
    const normalized = normalizeStatusMessage(message)
    const match = normalized.match(/^\[(Tab|App)\s+(\d+)\]\s*(.*)$/)
    if (!match) {
        return {
            normalized,
            scope: null,
            index: null,
            itemKey: null,
            body: normalized
        }
    }

    const scope = match[1].toLowerCase()
    const index = Number(match[2])

    return {
        normalized,
        scope,
        index,
        itemKey: `${scope}-${index}`,
        body: match[3].trim()
    }
}

function createLooseItemKey(kind, label) {
    return `${kind}:${String(label || '').trim().toLowerCase()}`
}

function buildLaunchItem({ itemKey, scope, label, kind = 'item' }) {
    const trimmedLabel = String(label || '').trim()
    if (!trimmedLabel) return null

    return {
        itemKey: itemKey || createLooseItemKey(kind || scope || 'item', trimmedLabel),
        label: trimmedLabel
    }
}

function cleanDisplayLabel(item) {
    if (!item) return ''
    if (item.includes('.') && (item.startsWith('http') || item.includes('://'))) {
        try {
            return new URL(item.startsWith('http') ? item : `https://${item}`).hostname.replace('www.', '')
        } catch {
            return item
        }
    }
    return item
}

function safeAutoLaunchText(value, fallback = '') {
    if (typeof value !== 'string') return fallback
    const text = value
        .replace(/[\u0000-\u001F\u007F]/g, ' ')
        .replace(/https?:\/\/[^\s]+/gi, '[redacted-url]')
        .replace(/[?#][A-Za-z0-9_=&%.-]+/g, '')
        .replace(/\s+/g, ' ')
        .trim()
    return text.length > 90 ? `${text.slice(0, 87).trim()}...` : text
}

function normalizeAutoLaunchStatus(status) {
    if (!status || typeof status !== 'object' || Array.isArray(status)) {
        return {
            statusCategory: 'idle',
            countdownSeconds: 0,
            presetLabel: '',
            itemCounts: { total: 0, browserTabs: 0, desktopApps: 0, hostFolders: 0, accountIntentions: 0, profileIntentions: 0 },
            blockerReasonCodes: [],
            recoveryHints: []
        }
    }
    const counts = status.itemCounts && typeof status.itemCounts === 'object' ? status.itemCounts : {}
    return {
        statusCategory: safeAutoLaunchText(status.statusCategory || status.status, 'idle'),
        countdownSeconds: Number.isSafeInteger(status.countdownSeconds) && status.countdownSeconds > 0 ? status.countdownSeconds : 0,
        presetLabel: safeAutoLaunchText(status.presetLabel, ''),
        itemCounts: {
            total: Number.isSafeInteger(counts.total) ? counts.total : 0,
            browserTabs: Number.isSafeInteger(counts.browserTabs) ? counts.browserTabs : 0,
            desktopApps: Number.isSafeInteger(counts.desktopApps) ? counts.desktopApps : 0,
            hostFolders: Number.isSafeInteger(counts.hostFolders) ? counts.hostFolders : 0,
            accountIntentions: Number.isSafeInteger(counts.accountIntentions) ? counts.accountIntentions : 0,
            profileIntentions: Number.isSafeInteger(counts.profileIntentions) ? counts.profileIntentions : 0
        },
        blockerReasonCodes: Array.isArray(status.blockerReasonCodes)
            ? status.blockerReasonCodes.slice(0, 5).map(code => safeAutoLaunchText(code, '')).filter(Boolean)
            : [],
        recoveryHints: Array.isArray(status.recoveryHints)
            ? status.recoveryHints.slice(0, 3).map(hint => safeAutoLaunchText(hint, '')).filter(Boolean)
            : []
    }
}

function parseSuccessItem(message) {
    const { itemKey, scope, body } = parseScopedStatus(message)
    if (!itemKey) return null
    const match = body.match(/^\[OK\]\s+(.+?)(?:\s+-\s+(?:ready|launched))?$/)
    if (!match) return null

    return buildLaunchItem({
        itemKey,
        scope,
        label: match[1],
        kind: 'success'
    })
}

function parseFailureItem(message) {
    const { itemKey, scope, body } = parseScopedStatus(message)
    if (!itemKey) return null
    const itemMatch = body.match(/^\[WARN\]\s+(.+?)(?:\s+-\s+(.+))?$/)
    if (!itemMatch) return null

    const item = buildLaunchItem({
        itemKey,
        scope,
        label: itemMatch[1],
        kind: 'failure'
    })
    if (!item) return null

    return {
        ...item,
        reason: (itemMatch[2] || 'Launch failed').trim()
    }
}

function cleanNotice(message) {
    return normalizeStatusMessage(message)
        .replace(/^\[(?:Tab|App)\s+\d+\]\s*/, '')
        .replace(/^\[(?:INFO|WARN|OK)\]\s*/, '')
        .trim()
}

function parseNoticeItem(message) {
    const { itemKey, body } = parseScopedStatus(message)
    if (!/^\[(?:INFO|WARN)\]\s+/.test(body)) return null

    const cleaned = cleanNotice(message)
    if (!cleaned) return null

    return {
        noticeKey: itemKey ? `${itemKey}:${cleaned}` : `notice:${cleaned}`,
        itemKey,
        message: cleaned
    }
}

function buildResultLaunchItem(item, index, fallbackType) {
    const itemType = item?.type || fallbackType
    const label = itemType === 'web' ? item?.url : item?.name
    if (!label) return null

    return buildLaunchItem({
        itemKey: item?.itemKey || `${itemType === 'web' ? 'tab' : 'app'}-${index + 1}`,
        scope: itemType === 'web' ? 'tab' : 'app',
        label,
        kind: itemType === 'web' ? 'tab' : 'app'
    })
}

function mergeLoadedItem(existing, nextItem) {
    if (!nextItem?.itemKey) return existing

    const existingIndex = existing.findIndex((item) => item.itemKey === nextItem.itemKey)
    if (existingIndex === -1) return [...existing, nextItem]

    const updated = [...existing]
    updated[existingIndex] = { ...updated[existingIndex], ...nextItem }
    return updated
}

function mergeFailedItem(existing, nextFailure) {
    if (!nextFailure?.itemKey) return existing

    const existingIndex = existing.findIndex((item) => item.itemKey === nextFailure.itemKey)
    if (existingIndex === -1) return [...existing, nextFailure]

    const updated = [...existing]
    updated[existingIndex] = { ...updated[existingIndex], ...nextFailure }
    return updated
}

function mergeSkippedItem(existing, nextSkipped) {
    return mergeFailedItem(existing, nextSkipped)
}

function mergeNoticeItem(existing, nextNotice) {
    if (!nextNotice?.noticeKey) return existing

    const existingIndex = existing.findIndex((notice) => notice.noticeKey === nextNotice.noticeKey)
    if (existingIndex === -1) return [...existing, nextNotice]

    const updated = [...existing]
    updated[existingIndex] = { ...updated[existingIndex], ...nextNotice }
    return updated
}

function removeFailureByKey(existing, itemKey) {
    if (!itemKey) return existing
    return existing.filter((item) => item.itemKey !== itemKey)
}

function removeSkippedByKey(existing, itemKey) {
    return removeFailureByKey(existing, itemKey)
}

function removeLoadedByKey(existing, itemKey) {
    if (!itemKey) return existing
    return existing.filter((item) => item.itemKey !== itemKey)
}

function removeNoticesByItemKey(existing, itemKey) {
    if (!itemKey) return existing
    return existing.filter((notice) => notice.itemKey !== itemKey)
}

function reconcileFinalNotices(existing, finalLoaded, finalFailed, finalSkipped = []) {
    const resolvedKeys = new Set([
        ...finalLoaded.map((item) => item.itemKey).filter(Boolean),
        ...finalFailed.map((item) => item.itemKey).filter(Boolean),
        ...finalSkipped.map((item) => item.itemKey).filter(Boolean)
    ])

    return existing.filter((notice) => !notice.itemKey || !resolvedKeys.has(notice.itemKey))
}

export default function LaunchingScreen({ workspace, autoLaunch = false, onSettingsClick }) {
    const [phase, setPhase] = useState('launching')
    const [progress, setProgress] = useState(0)
    const [totalItems, setTotalItems] = useState(0)
    const [loadedItems, setLoadedItems] = useState([])
    const [failedItems, setFailedItems] = useState([])
    const [skippedItems, setSkippedItems] = useState([])
    const [notices, setNotices] = useState([])
    const [liveStatus, setLiveStatus] = useState('Preparing workspace...')
    const [errorMsg, setErrorMsg] = useState(null)
    const [savingSession, setSavingSession] = useState(false)
    const [saveSuccess, setSaveSuccess] = useState(false)
    const [isClosing, setIsClosing] = useState(false)
    const [autoLaunchStatus, setAutoLaunchStatus] = useState(() => normalizeAutoLaunchStatus(null))

    const beginWorkspaceLaunch = async () => {
        if (!workspace) return
        setLoadedItems([])
        setFailedItems([])
        setSkippedItems([])
        setNotices([])
        setLiveStatus('Preparing workspace...')
        setErrorMsg(null)
        setProgress(0)
        setPhase('launching')
        try {
            const result = await window.wipesnap.launchWorkspace(workspace)
            if (result && result.success === false) {
                setPhase('error')
                setErrorMsg(result.error || 'Workspace launch could not start.')
            }
        } catch (err) {
            setPhase('error')
            setErrorMsg(err.message)
        }
    }

    useEffect(() => {
        setLoadedItems([])
        setFailedItems([])
        setSkippedItems([])
        setNotices([])
        setLiveStatus('Preparing workspace...')
        setErrorMsg(null)
        setProgress(0)
        setPhase('launching')
    }, [workspace, autoLaunch])

    useEffect(() => {
        if (totalItems === 0) {
            setProgress(100)
            return
        }
        const processed = loadedItems.length + failedItems.length + skippedItems.length
        setProgress(Math.min(100, Math.round((processed / totalItems) * 100)))
    }, [loadedItems, failedItems, skippedItems, totalItems])

    useEffect(() => {
        if (!workspace) return

        const enabledTabs = workspace.webTabs?.filter((t) => t.enabled) || []
        const enabledApps = workspace.desktopApps?.filter((a) => a.enabled) || []
        const total = enabledTabs.length + enabledApps.length

        setTotalItems(total)
        if (total === 0 || !autoLaunch) {
            setPhase('ready')
            setProgress(100)
        }

        const cleanupStatus = window.wipesnap.onLaunchStatus((rawMessage) => {
            const message = normalizeStatusMessage(rawMessage)
            if (!message) return

            setLiveStatus(cleanNotice(message))

            const successItem = parseSuccessItem(message)
            if (successItem) {
                setFailedItems((prev) => removeFailureByKey(prev, successItem.itemKey))
                setSkippedItems((prev) => removeSkippedByKey(prev, successItem.itemKey))
                setNotices((prev) => removeNoticesByItemKey(prev, successItem.itemKey))
                setLoadedItems((prev) => mergeLoadedItem(prev, successItem))
                return
            }

            const failureItem = parseFailureItem(message)
            if (failureItem) {
                setLoadedItems((prev) => removeLoadedByKey(prev, failureItem.itemKey))
                setNotices((prev) => removeNoticesByItemKey(prev, failureItem.itemKey))
                if (/^Skipped\b/i.test(failureItem.reason || '')) {
                    setFailedItems((prev) => removeFailureByKey(prev, failureItem.itemKey))
                    setSkippedItems((prev) => mergeSkippedItem(prev, failureItem))
                } else {
                    setSkippedItems((prev) => removeSkippedByKey(prev, failureItem.itemKey))
                    setFailedItems((prev) => mergeFailedItem(prev, failureItem))
                }
                return
            }

            if (message.includes('[INFO]') || message.includes('[WARN]')) {
                const notice = parseNoticeItem(message)
                setNotices((prev) => mergeNoticeItem(prev, notice))
            }
        })

        const cleanupComplete = window.wipesnap.onLaunchComplete((result) => {
            if (!result.success) {
                setPhase('error')
                setErrorMsg(result.error)
                return
            }

            if (result.results?.metadataOnly === true) {
                setLoadedItems([])
                setFailedItems([])
                setSkippedItems([])
                setNotices([])
                setPhase('ready')
                setProgress(100)
                setLiveStatus('Workspace launch complete.')
                return
            }

            const finalLoaded = []
            const finalFailed = []
            const finalSkipped = []
            const webResults = result.results?.webResults || []
            const appResults = result.results?.appResults || []

            const appendFinalResults = (items, fallbackType) => {
                for (const [index, item] of items.entries()) {
                    const finalItem = buildResultLaunchItem(item, index, fallbackType)
                    if (!finalItem) continue

                    if (item.skipped) {
                        finalSkipped.push({
                            ...finalItem,
                            reason: item.error || item.reason || 'Skipped'
                        })
                    } else if (item.success) {
                        finalLoaded.push(finalItem)
                    } else {
                        finalFailed.push({
                            ...finalItem,
                            reason: item.error || 'Launch failed'
                        })
                    }
                }
            }

            appendFinalResults(webResults, 'web')
            appendFinalResults(appResults, 'app')

            setLoadedItems(finalLoaded)
            setFailedItems(finalFailed)
            setSkippedItems(finalSkipped)
            setNotices((prev) => reconcileFinalNotices(prev, finalLoaded, finalFailed, finalSkipped))
            setPhase('ready')
            setProgress(100)
            setLiveStatus(
                finalFailed.length > 0
                    ? 'Workspace finished with some failures.'
                    : finalSkipped.length > 0
                        ? 'Workspace launch complete. Some browser-owned pages were skipped.'
                        : 'Workspace launch complete.'
            )
        })

        if (shouldAutoStartRendererLaunch({ autoLaunch, total })) {
            beginWorkspaceLaunch()
        }

        return () => {
            cleanupStatus()
            cleanupComplete()
        }
    }, [workspace, autoLaunch])

    useEffect(() => {
        if (!window.wipesnap.autoLaunch) return undefined
        let active = true
        const applyStatus = (status) => {
            if (!active) return
            const safeStatus = normalizeAutoLaunchStatus(status)
            setAutoLaunchStatus(safeStatus)
            if (safeStatus.statusCategory === 'launching') {
                setPhase('launching')
                setLiveStatus('Trusted auto-launch started.')
                if (safeStatus.itemCounts.total > 0) setTotalItems(safeStatus.itemCounts.total)
            }
            if (safeStatus.statusCategory === 'countdown' && safeStatus.itemCounts.total > 0) {
                setTotalItems(safeStatus.itemCounts.total)
            }
        }
        window.wipesnap.autoLaunch.getStatus().then(applyStatus).catch(() => {})
        const cleanup = window.wipesnap.autoLaunch.onStatus(applyStatus)
        return () => {
            active = false
            cleanup()
        }
    }, [])

    const handleSaveSession = async () => {
        setSavingSession(true)
        setSaveSuccess(false)
        const result = await window.wipesnap.saveCurrentSession()
        setSavingSession(false)
        if (result.success) {
            setSaveSuccess(true)
            setTimeout(() => setSaveSuccess(false), 3000)
        }
    }

    const handleQuit = async () => {
        if (isClosing) return
        setIsClosing(true)
        try {
            await window.wipesnap.quitAndRelaunch({ closeApps: true })
        } catch (_) { }
        window.wipesnap.close()
    }

    const handleCancelAutoLaunch = async () => {
        try {
            const status = await window.wipesnap.autoLaunch?.cancelCurrentAttempt()
            setAutoLaunchStatus(normalizeAutoLaunchStatus(status))
        } catch (_) { }
    }

    const handleDisableAutoLaunch = async () => {
        try {
            const status = await window.wipesnap.autoLaunch?.disable()
            setAutoLaunchStatus(normalizeAutoLaunchStatus(status))
        } catch (_) { }
    }

    const handleAutoLaunchNow = async () => {
        try {
            setPhase('launching')
            setLiveStatus('Preparing trusted auto-launch...')
            const result = await window.wipesnap.autoLaunch?.launchNow()
            if (result?.status) setAutoLaunchStatus(normalizeAutoLaunchStatus(result.status))
        } catch (err) {
            setPhase('error')
            setErrorMsg(err.message)
        }
    }

    const statusSummary = useMemo(() => {
        if (failedItems.length > 0) {
            return `${loadedItems.length} loaded, ${failedItems.length} failed${skippedItems.length > 0 ? `, ${skippedItems.length} skipped` : ''}`
        }
        if (skippedItems.length > 0) {
            return `${loadedItems.length} loaded, ${skippedItems.length} skipped`
        }
        return `${loadedItems.length} of ${totalItems} items loaded`
    }, [loadedItems.length, failedItems.length, skippedItems.length, totalItems])

    const readyTitle = failedItems.length > 0 ? 'Workspace Partially Ready' : 'Workspace Ready'
    const readySubtitle = failedItems.length > 0
        ? `${loadedItems.length} launched, ${failedItems.length} failed${skippedItems.length > 0 ? `, ${skippedItems.length} skipped` : ''}`
        : skippedItems.length > 0
            ? `${loadedItems.length} launched, ${skippedItems.length} skipped`
            : loadedItems.length > 0
                ? `${loadedItems.length} item${loadedItems.length !== 1 ? 's' : ''} launched`
                : 'All set'

    const showAutoLaunchCountdown = autoLaunchStatus.statusCategory === 'countdown'
    const showAutoLaunchBlocked = autoLaunchStatus.statusCategory === 'blocked' &&
        autoLaunchStatus.blockerReasonCodes.length > 0

    return (
        <>
            {isClosing && (
                <div
                    style={{
                        position: 'fixed', inset: 0, zIndex: 100,
                        display: 'flex', flexDirection: 'column',
                        alignItems: 'center', justifyContent: 'center',
                        background: 'rgba(10, 10, 20, 0.97)'
                    }}
                    className="animate-fade-in"
                >
                    <div className="spinner" style={{ width: 28, height: 28, marginBottom: 16 }} />
                    <h2 style={{ fontSize: 16, fontWeight: 600, color: '#fff', marginBottom: 6 }}>Closing Workspace</h2>
                    <p style={{ fontSize: 12, color: '#8888a0' }}>Syncing data & cleaning up...</p>
                    <p style={{ fontSize: 10, color: '#555568', marginTop: 16 }}>Please don&apos;t unplug your USB drive</p>
                </div>
            )}

            <div className="card p-6 w-full max-w-sm animate-slide-up" style={{ maxHeight: 560 }}>
                {phase === 'launching' && (
                    <div className="flex flex-col items-center animate-fade-in">
                        <div className="w-14 h-14 mx-auto mb-4 rounded-full flex items-center justify-center bg-[#1a1a2e]">
                            <div className="spinner" style={{ width: 22, height: 22, borderWidth: 2 }} />
                        </div>

                        <h1 className="text-base font-semibold text-white mb-1">Launching Workspace</h1>
                        <p className="text-secondary text-xs mb-2">{statusSummary}</p>
                        <p className="text-muted text-center mb-4" style={{ fontSize: 10, minHeight: 28 }}>
                            {liveStatus}
                        </p>

                        <div className="w-full h-1.5 rounded-full bg-[#14141c] mb-4 overflow-hidden">
                            <div
                                className="h-full rounded-full transition-all duration-500 ease-out"
                                style={{
                                    width: `${progress}%`,
                                    background: failedItems.length > 0
                                        ? 'linear-gradient(90deg, #d59a5b, #d57b5b)'
                                        : 'linear-gradient(90deg, #5b7bd5, #7b5bd5)'
                                }}
                            />
                        </div>

                        <div className="w-full space-y-3" style={{ maxHeight: 260, overflowY: 'auto' }}>
                            {loadedItems.length > 0 && (
                                <div className="space-y-1.5">
                                    {loadedItems.map((item, i) => (
                                        <div key={item.itemKey || `ok-${i}`} className="flex items-center gap-2 animate-fade-in">
                                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#4a9" strokeWidth="3" strokeLinecap="round">
                                                <polyline points="20 6 9 17 4 12" />
                                            </svg>
                                            <span className="text-xs text-secondary truncate">{cleanDisplayLabel(item.label)}</span>
                                        </div>
                                    ))}
                                </div>
                            )}

                            {failedItems.length > 0 && (
                                <div className="pt-2 border-t border-[#2a2432] space-y-2">
                                    <p className="text-xs font-medium text-[#f0b36b]">Failed items</p>
                                    {failedItems.map((item, i) => (
                                        <div key={item.itemKey || `warn-${i}`} className="flex items-start gap-2 animate-fade-in">
                                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#d57b5b" strokeWidth="2.5" strokeLinecap="round">
                                                <circle cx="12" cy="12" r="9" />
                                                <line x1="12" y1="8" x2="12" y2="13" />
                                                <circle cx="12" cy="16.5" r="0.8" fill="#d57b5b" stroke="none" />
                                            </svg>
                                            <div className="min-w-0">
                                                <div className="text-xs text-white truncate">{cleanDisplayLabel(item.label)}</div>
                                                <div className="text-[10px] text-[#c08e86] break-words">{item.reason}</div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}

                            {skippedItems.length > 0 && (
                                <div className="pt-2 border-t border-[#2a2432] space-y-2">
                                    <p className="text-xs font-medium text-[#d4a44a]">Skipped items</p>
                                    {skippedItems.map((item, i) => (
                                        <div key={item.itemKey || `skip-${i}`} className="flex items-start gap-2 animate-fade-in">
                                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#d4a44a" strokeWidth="2.5" strokeLinecap="round">
                                                <circle cx="12" cy="12" r="9" />
                                                <line x1="12" y1="8" x2="12" y2="13" />
                                                <circle cx="12" cy="16.5" r="0.8" fill="#d4a44a" stroke="none" />
                                            </svg>
                                            <div className="min-w-0">
                                                <div className="text-xs text-white truncate">{cleanDisplayLabel(item.label)}</div>
                                                <div className="text-[10px] text-[#d4a44a] break-words">{item.reason}</div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}

                            {notices.length > 0 && (
                                <div className="pt-2 border-t border-[#232335] space-y-1.5">
                                    <p className="text-xs font-medium text-[#9ab0ff]">Notes</p>
                                    {notices.map((notice, i) => (
                                        <div key={notice.noticeKey || `note-${i}`} className="text-[10px] text-[#9ca3c8] break-words">
                                            {notice.message}
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {phase === 'ready' && (
                    <div className="flex flex-col animate-fade-in">
                        <div className="text-center mb-4">
                            <div
                                className="w-14 h-14 mx-auto mb-3 rounded-full flex items-center justify-center"
                                style={{ background: failedItems.length > 0 ? '#2a2416' : '#1a2a1a' }}
                            >
                                {failedItems.length > 0 ? (
                                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#f0b36b" strokeWidth="2.5" strokeLinecap="round">
                                        <path d="M12 9v4" />
                                        <circle cx="12" cy="16.5" r="0.8" fill="#f0b36b" stroke="none" />
                                        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                                    </svg>
                                ) : (
                                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#4a9" strokeWidth="2.5" strokeLinecap="round">
                                        <polyline points="20 6 9 17 4 12" />
                                    </svg>
                                )}
                            </div>
                            <h1 className="text-lg font-semibold text-white">{readyTitle}</h1>
                            <p className="text-secondary text-xs mt-1">{readySubtitle}</p>
                        </div>

                        {(loadedItems.length > 0 || failedItems.length > 0 || skippedItems.length > 0) && (
                            <div className="mb-4 p-3 rounded-lg bg-[#14141c]" style={{ maxHeight: 180, overflowY: 'auto' }}>
                                <div className="space-y-2">
                                    {loadedItems.map((item, i) => (
                                        <div key={item.itemKey || `ready-ok-${i}`} className="flex items-center gap-2.5">
                                            <div className="w-5 h-5 rounded flex items-center justify-center flex-shrink-0" style={{ background: '#1a2a1a' }}>
                                                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#4a9" strokeWidth="3" strokeLinecap="round">
                                                    <polyline points="20 6 9 17 4 12" />
                                                </svg>
                                            </div>
                                            <span className="text-xs text-white truncate">{cleanDisplayLabel(item.label)}</span>
                                        </div>
                                    ))}

                                    {skippedItems.map((item, i) => (
                                        <div key={item.itemKey || `ready-skip-${i}`} className="flex items-start gap-2.5">
                                            <div className="w-5 h-5 rounded flex items-center justify-center flex-shrink-0" style={{ background: '#2a2416' }}>
                                                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#d4a44a" strokeWidth="2.5" strokeLinecap="round">
                                                    <line x1="12" y1="7" x2="12" y2="13" />
                                                    <circle cx="12" cy="17" r="0.8" fill="#d4a44a" stroke="none" />
                                                    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                                                </svg>
                                            </div>
                                            <div className="min-w-0">
                                                <div className="text-xs text-white truncate">{cleanDisplayLabel(item.label)}</div>
                                                <div className="text-[10px] text-[#d4a44a] break-words">{item.reason}</div>
                                            </div>
                                        </div>
                                    ))}

                                    {failedItems.map((item, i) => (
                                        <div key={item.itemKey || `ready-warn-${i}`} className="flex items-start gap-2.5">
                                            <div className="w-5 h-5 rounded flex items-center justify-center flex-shrink-0" style={{ background: '#2a1e1a' }}>
                                                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#d57b5b" strokeWidth="2.5" strokeLinecap="round">
                                                    <line x1="12" y1="7" x2="12" y2="13" />
                                                    <circle cx="12" cy="17" r="0.8" fill="#d57b5b" stroke="none" />
                                                    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                                                </svg>
                                            </div>
                                            <div className="min-w-0">
                                                <div className="text-xs text-white truncate">{cleanDisplayLabel(item.label)}</div>
                                                <div className="text-[10px] text-[#c08e86] break-words">{item.reason}</div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {notices.length > 0 && (
                            <div className="mb-4 p-3 rounded-lg bg-[#121626] border border-[#27304d]">
                                <div className="space-y-1.5">
                                    {notices.map((notice, i) => (
                                        <div key={notice.noticeKey || `ready-note-${i}`} className="text-[10px] text-[#aab7e8] break-words">
                                            {notice.message}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {showAutoLaunchCountdown && (
                            <div className="mb-4 p-3 rounded-lg bg-[#121626] border border-[#27304d]">
                                <div className="flex items-start justify-between gap-3 mb-2">
                                    <div className="min-w-0">
                                        <p className="text-xs font-medium text-white">Trusted auto-launch</p>
                                        <p className="text-[10px] text-[#aab7e8] truncate">
                                            {autoLaunchStatus.presetLabel || 'Selected preset'}
                                        </p>
                                    </div>
                                    <div className="text-right flex-shrink-0">
                                        <p className="text-base font-semibold text-white">{autoLaunchStatus.countdownSeconds}</p>
                                        <p className="text-[9px] text-[#8793c2]">sec</p>
                                    </div>
                                </div>
                                <p className="text-[10px] text-[#9ca3c8] mb-3">
                                    {autoLaunchStatus.itemCounts.total} items: {autoLaunchStatus.itemCounts.browserTabs} tabs, {autoLaunchStatus.itemCounts.desktopApps + autoLaunchStatus.itemCounts.hostFolders} desktop
                                </p>
                                <div className="grid grid-cols-3 gap-2">
                                    <button className="btn-secondary text-[10px] py-1.5" onClick={handleCancelAutoLaunch}>
                                        Cancel
                                    </button>
                                    <button className="btn-primary text-[10px] py-1.5" onClick={handleAutoLaunchNow}>
                                        Launch now
                                    </button>
                                    <button className="text-[10px] py-1.5 rounded-md border border-[#3a2a2a] text-[#d44] hover:bg-[#2a1a1a] transition-colors" onClick={handleDisableAutoLaunch}>
                                        Disable
                                    </button>
                                </div>
                            </div>
                        )}

                        {showAutoLaunchBlocked && (
                            <div className="mb-4 p-3 rounded-lg bg-[#1b1718] border border-[#3a2a2a]">
                                <p className="text-xs font-medium text-[#f0b36b] mb-1">Auto-launch blocked</p>
                                <p className="text-[10px] text-[#c08e86] break-words">
                                    {autoLaunchStatus.blockerReasonCodes.join(', ')}
                                </p>
                                {autoLaunchStatus.recoveryHints[0] && (
                                    <p className="text-[10px] text-[#9ca3c8] mt-1">{autoLaunchStatus.recoveryHints[0]}</p>
                                )}
                            </div>
                        )}

                        <div className="space-y-2">
                            {totalItems > 0 && loadedItems.length === 0 && failedItems.length === 0 && skippedItems.length === 0 && (
                                <button
                                    className="btn-primary w-full text-sm py-2.5"
                                    onClick={beginWorkspaceLaunch}
                                >
                                    Launch Workspace
                                </button>
                            )}

                            <button
                                className={`${totalItems > 0 && loadedItems.length === 0 && failedItems.length === 0 && skippedItems.length === 0 ? 'btn-secondary' : 'btn-primary'} w-full text-sm py-2.5`}
                                disabled={savingSession}
                                onClick={handleSaveSession}
                            >
                                {savingSession ? (
                                    <span className="flex items-center justify-center gap-2">
                                        <div className="spinner" style={{ width: 12, height: 12, borderWidth: 2 }} />
                                        Saving...
                                    </span>
                                ) : saveSuccess ? (
                                    <span className="flex items-center justify-center gap-1.5">
                                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                                            <polyline points="20 6 9 17 4 12" />
                                        </svg>
                                        Saved!
                                    </span>
                                ) : (
                                    <span className="flex items-center justify-center gap-1.5">
                                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                                            <path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z" />
                                            <polyline points="17 21 17 13 7 13 7 21" />
                                            <polyline points="7 3 7 8 15 8" />
                                        </svg>
                                        Save Session
                                    </span>
                                )}
                            </button>

                            <div className="flex gap-2">
                                <button className="btn-secondary flex-1 text-xs py-2" onClick={onSettingsClick}>
                                    <span className="flex items-center justify-center gap-1.5">
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                                            <circle cx="12" cy="12" r="3" />
                                            <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
                                        </svg>
                                        Settings
                                    </span>
                                </button>

                                <button
                                    className="flex-1 text-xs py-2 rounded-md border border-[#3a2a2a] text-[#d44] hover:bg-[#2a1a1a] transition-colors"
                                    onClick={handleQuit}
                                >
                                    <span className="flex items-center justify-center gap-1.5">
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                                            <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" />
                                            <polyline points="16 17 21 12 16 7" />
                                            <line x1="21" y1="12" x2="9" y2="12" />
                                        </svg>
                                        Quit
                                    </span>
                                </button>
                            </div>
                        </div>

                        <p className="text-muted text-center mt-3" style={{ fontSize: 10 }}>
                            Save your tabs & logins before unplugging
                        </p>
                    </div>
                )}

                {phase === 'error' && (
                    <div className="flex flex-col items-center animate-fade-in">
                        <div className="w-14 h-14 mx-auto mb-4 rounded-full flex items-center justify-center bg-[#2a1a1a]">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#d44" strokeWidth="2" strokeLinecap="round">
                                <circle cx="12" cy="12" r="10" />
                                <line x1="15" y1="9" x2="9" y2="15" />
                                <line x1="9" y1="9" x2="15" y2="15" />
                            </svg>
                        </div>
                        <h1 className="text-base font-semibold text-white mb-1">Launch Failed</h1>
                        <p className="text-error text-xs text-center mb-4">{errorMsg}</p>

                        <div className="flex gap-2 w-full">
                            <button className="btn-secondary flex-1 text-sm" onClick={handleQuit}>
                                Quit
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </>
    )
}
