import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { realtimeVAPTAPI, createRealtimeWebSocket } from '@/services/api'
import { showToast } from '@/components/ToastSystem'
import { GlowingCard } from '@/components/GlowingCard'
import {
    PlayIcon,
    StopIcon,
    ChartBarIcon,
    ShieldCheckIcon,
    ExclamationTriangleIcon,
    CheckCircleIcon,
    ClockIcon
} from '@heroicons/react/24/solid'
import { staggerContainer, staggerItem } from '@/utils/animations'

interface RealtimeMessage {
    type: string
    tool?: string
    line?: string
    vulnerability?: {
        type: string
        severity: string
        details: string
    }
    percentage?: number
    findings_count?: number
    duration?: number
    timestamp?: string
}

interface ToolStatus {
    name: string
    status: 'pending' | 'running' | 'complete' | 'error'
    findings: number
    duration?: number
    logs: string[]
}

export default function RealtimeVAPT() {
    const [target, setTarget] = useState('')
    const [selectedTools, setSelectedTools] = useState<string[]>([])
    const [availableTools, setAvailableTools] = useState<any[]>([])
    const [scanType, setScanType] = useState('standard')
    const [isScanning, setIsScanning] = useState(false)
    const [scanId, setScanId] = useState<string | null>(null)
    const [toolStatuses, setToolStatuses] = useState<Record<string, ToolStatus>>({})
    const [messages, setMessages] = useState<RealtimeMessage[]>([])
    const [vulnerabilities, setVulnerabilities] = useState<any[]>([])
    const [stats, setStats] = useState<any>(null)
    const wsRef = useRef<WebSocket | null>(null)
    const messagesEndRef = useRef<HTMLDivElement>(null)

    useEffect(() => {
        loadTools()
        loadStats()
    }, [])

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, [messages])

    const loadTools = async () => {
        try {
            const response = await realtimeVAPTAPI.getTools()
            const toolsData = response.data.tools || {}
            setAvailableTools(Object.keys(toolsData).map(name => ({
                name,
                ...toolsData[name]
            })))
        } catch (error: any) {
            showToast.error('Failed to load tools')
        }
    }

    const loadStats = async () => {
        try {
            const response = await realtimeVAPTAPI.getStats()
            setStats(response.data)
        } catch (error: any) {
            console.error('Failed to load stats:', error)
        }
    }

    const handleQuickScan = async () => {
        if (!target) {
            showToast.error('Please enter a target')
            return
        }

        try {
            const response = await realtimeVAPTAPI.quickScan(target)
            startRealtimeScan(response.data)
        } catch (error: any) {
            showToast.error(error.response?.data?.detail || 'Failed to start scan')
        }
    }

    const handleFullScan = async () => {
        if (!target) {
            showToast.error('Please enter a target')
            return
        }

        try {
            const response = await realtimeVAPTAPI.fullScan(target)
            startRealtimeScan(response.data)
        } catch (error: any) {
            showToast.error(error.response?.data?.detail || 'Failed to start scan')
        }
    }

    const handleCustomScan = async () => {
        if (!target) {
            showToast.error('Please enter a target')
            return
        }
        if (selectedTools.length === 0) {
            showToast.error('Please select at least one tool')
            return
        }

        try {
            const response = await realtimeVAPTAPI.customScan(
                target,
                selectedTools,
                scanType,
                true,
                5
            )
            startRealtimeScan(response.data)
        } catch (error: any) {
            showToast.error(error.response?.data?.detail || 'Failed to start scan')
        }
    }

    const startRealtimeScan = (scanData: any) => {
        setScanId(scanData.scan_id)
        setIsScanning(true)
        setMessages([])
        setVulnerabilities([])
        setToolStatuses({})

        // Initialize tool statuses
        const tools = scanData.tools || selectedTools
        const initialStatuses: Record<string, ToolStatus> = {}
        tools.forEach((tool: string) => {
            initialStatuses[tool] = {
                name: tool,
                status: 'pending',
                findings: 0,
                logs: []
            }
        })
        setToolStatuses(initialStatuses)

        // Connect WebSocket
        wsRef.current = createRealtimeWebSocket(scanData.scan_id, handleWebSocketMessage)

        showToast.success(`Scan started! ID: ${scanData.scan_id}`)
    }

    const handleWebSocketMessage = (message: RealtimeMessage) => {
        setMessages(prev => [...prev, message])

        const { type, tool } = message

        if (type === 'tool_start' && tool) {
            setToolStatuses(prev => ({
                ...prev,
                [tool]: { ...prev[tool], status: 'running' }
            }))
        } else if (type === 'log' && tool && message.line) {
            setToolStatuses(prev => ({
                ...prev,
                [tool]: {
                    ...prev[tool],
                    logs: [...(prev[tool]?.logs || []), message.line!].slice(-50) // Keep last 50 logs
                }
            }))
        } else if (type === 'vulnerability_found' && tool) {
            setVulnerabilities(prev => [...prev, { ...message.vulnerability, tool, timestamp: message.timestamp }])
            setToolStatuses(prev => ({
                ...prev,
                [tool]: {
                    ...prev[tool],
                    findings: message.findings_count || prev[tool].findings + 1
                }
            }))
        } else if (type === 'tool_complete' && tool) {
            setToolStatuses(prev => ({
                ...prev,
                [tool]: {
                    ...prev[tool],
                    status: message.duration ? 'complete' : 'error',
                    duration: message.duration,
                    findings: message.findings_count || prev[tool].findings
                }
            }))
        } else if (type === 'scan_complete' || type === 'parallel_complete') {
            setIsScanning(false)
            showToast.success('Scan completed!')
        } else if (type === 'scan_error') {
            setIsScanning(false)
            showToast.error('Scan failed')
        }
    }

    const stopScan = () => {
        if (wsRef.current) {
            wsRef.current.close()
            wsRef.current = null
        }
        setIsScanning(false)
        showToast.info('Scan stopped')
    }

    const toggleTool = (toolName: string) => {
        setSelectedTools(prev =>
            prev.includes(toolName)
                ? prev.filter(t => t !== toolName)
                : [...prev, toolName]
        )
    }

    const getSeverityColor = (severity: string) => {
        switch (severity.toLowerCase()) {
            case 'critical': return 'text-red-500'
            case 'high': return 'text-orange-500'
            case 'medium': return 'text-yellow-500'
            case 'low': return 'text-blue-500'
            default: return 'text-gray-500'
        }
    }

    const getStatusIcon = (status: string) => {
        switch (status) {
            case 'running': return <ClockIcon className="w-5 h-5 text-blue-500 animate-spin" />
            case 'complete': return <CheckCircleIcon className="w-5 h-5 text-green-500" />
            case 'error': return <ExclamationTriangleIcon className="w-5 h-5 text-red-500" />
            default: return <ClockIcon className="w-5 h-5 text-gray-500" />
        }
    }

    return (
        <motion.div
            variants={staggerContainer}
            initial="hidden"
            animate="visible"
            className="space-y-8"
        >
            <motion.div variants={staggerItem}>
                <h1 className="text-4xl font-bold text-white mb-2">🚀 Real-Time VAPT</h1>
                <p className="text-gray-400">Live vulnerability assessment with 88+ security tools</p>
            </motion.div>

            {/* Stats Cards */}
            {stats && (
                <motion.div variants={staggerItem} className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <GlowingCard title="Active Connections" accentColor="blue">
                        <div className="text-3xl font-bold text-white">{stats.active_connections || 0}</div>
                    </GlowingCard>
                    <GlowingCard title="Docker Status" accentColor="green">
                        <div className="text-lg font-semibold text-white">
                            {stats.docker_available ? '✅ Available' : '❌ Unavailable'}
                        </div>
                    </GlowingCard>
                    <GlowingCard title="Active Executions" accentColor="purple">
                        <div className="text-3xl font-bold text-white">{stats.active_executions || 0}</div>
                    </GlowingCard>
                </motion.div>
            )}

            {/* Scan Configuration */}
            <motion.div variants={staggerItem}>
                <GlowingCard title="Scan Configuration" accentColor="cyan">
                    <div className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium text-gray-300 mb-2">Target</label>
                            <input
                                type="text"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                placeholder="https://example.com or 192.168.1.1"
                                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 text-white"
                                disabled={isScanning}
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-300 mb-2">Scan Type</label>
                            <select
                                value={scanType}
                                onChange={(e) => setScanType(e.target.value)}
                                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 text-white"
                                disabled={isScanning}
                            >
                                <option value="quick">Quick (Fast)</option>
                                <option value="standard">Standard (Recommended)</option>
                                <option value="full">Full (Comprehensive)</option>
                                <option value="aggressive">Aggressive (Deep)</option>
                            </select>
                        </div>

                        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                            <button
                                onClick={handleQuickScan}
                                disabled={isScanning}
                                className="flex items-center justify-center gap-2 px-4 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg disabled:opacity-50 transition-colors"
                            >
                                <PlayIcon className="w-5 h-5" />
                                Quick Scan
                            </button>
                            <button
                                onClick={handleFullScan}
                                disabled={isScanning}
                                className="flex items-center justify-center gap-2 px-4 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-lg disabled:opacity-50 transition-colors"
                            >
                                <ShieldCheckIcon className="w-5 h-5" />
                                Full Scan
                            </button>
                            {isScanning && (
                                <button
                                    onClick={stopScan}
                                    className="flex items-center justify-center gap-2 px-4 py-3 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
                                >
                                    <StopIcon className="w-5 h-5" />
                                    Stop
                                </button>
                            )}
                        </div>
                    </div>
                </GlowingCard>
            </motion.div>

            {/* Tool Selection */}
            <motion.div variants={staggerItem}>
                <GlowingCard title="Available Tools (Select for Custom Scan)" accentColor="green">
                    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
                        {availableTools.slice(0, 12).map((tool) => (
                            <button
                                key={tool.name}
                                onClick={() => toggleTool(tool.name)}
                                disabled={isScanning}
                                className={`px-3 py-2 rounded-lg text-sm font-medium transition-all ${selectedTools.includes(tool.name)
                                        ? 'bg-green-600 text-white'
                                        : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                                    } disabled:opacity-50`}
                            >
                                {tool.name}
                            </button>
                        ))}
                    </div>
                    {selectedTools.length > 0 && (
                        <button
                            onClick={handleCustomScan}
                            disabled={isScanning}
                            className="mt-4 w-full flex items-center justify-center gap-2 px-4 py-3 bg-gradient-to-r from-green-600 to-blue-600 text-white rounded-lg disabled:opacity-50"
                        >
                            <PlayIcon className="w-5 h-5" />
                            Start Custom Scan ({selectedTools.length} tools)
                        </button>
                    )}
                </GlowingCard>
            </motion.div>

            {/* Tool Status */}
            {Object.keys(toolStatuses).length > 0 && (
                <motion.div variants={staggerItem}>
                    <GlowingCard title="Tool Status" accentColor="blue">
                        <div className="space-y-2">
                            {Object.values(toolStatuses).map((tool) => (
                                <div key={tool.name} className="flex items-center justify-between p-3 bg-gray-800 rounded-lg">
                                    <div className="flex items-center gap-3">
                                        {getStatusIcon(tool.status)}
                                        <span className="font-medium text-white">{tool.name}</span>
                                    </div>
                                    <div className="flex items-center gap-4 text-sm">
                                        <span className="text-gray-400">
                                            {tool.findings} finding{tool.findings !== 1 ? 's' : ''}
                                        </span>
                                        {tool.duration && (
                                            <span className="text-gray-400">{tool.duration.toFixed(1)}s</span>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </GlowingCard>
                </motion.div>
            )}

            {/* Vulnerabilities */}
            {vulnerabilities.length > 0 && (
                <motion.div variants={staggerItem}>
                    <GlowingCard title={`Vulnerabilities (${vulnerabilities.length})`} accentColor="red">
                        <div className="space-y-2 max-h-96 overflow-y-auto">
                            <AnimatePresence>
                                {vulnerabilities.map((vuln, index) => (
                                    <motion.div
                                        key={index}
                                        initial={{ opacity: 0, x: -20 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        className="p-3 bg-gray-800 border-l-4 border-red-500 rounded-lg"
                                    >
                                        <div className="flex items-start justify-between">
                                            <div>
                                                <div className="flex items-center gap-2 mb-1">
                                                    <ExclamationTriangleIcon className={`w-4 h-4 ${getSeverityColor(vuln.severity)}`} />
                                                    <span className={`font-semibold ${getSeverityColor(vuln.severity)}`}>
                                                        {vuln.severity?.toUpperCase()}
                                                    </span>
                                                    <span className="text-gray-400 text-sm">•</span>
                                                    <span className="text-gray-400 text-sm">{vuln.type}</span>
                                                </div>
                                                <p className="text-sm text-gray-300">{vuln.details}</p>
                                            </div>
                                            <span className="text-xs text-gray-500">{vuln.tool}</span>
                                        </div>
                                    </motion.div>
                                ))}
                            </AnimatePresence>
                        </div>
                    </GlowingCard>
                </motion.div>
            )}

            {/* Live Logs */}
            {messages.length > 0 && (
                <motion.div variants={staggerItem}>
                    <GlowingCard title="Live Logs" accentColor="cyan">
                        <div className="bg-black rounded-lg p-4 font-mono text-xs max-h-64 overflow-y-auto">
                            {messages.slice(-50).map((msg, index) => (
                                <div key={index} className="text-green-400 mb-1">
                                    <span className="text-gray-500">[{msg.type}]</span>{' '}
                                    {msg.tool && <span className="text-blue-400">{msg.tool}:</span>}{' '}
                                    {msg.line || JSON.stringify(msg).slice(0, 100)}
                                </div>
                            ))}
                            <div ref={messagesEndRef} />
                        </div>
                    </GlowingCard>
                </motion.div>
            )}
        </motion.div>
    )
}
