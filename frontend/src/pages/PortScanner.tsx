import { useState } from 'react'
import { motion } from 'framer-motion'
import { scanAPI } from '@/services/api'
import { showToast } from '@/components/ToastSystem'
import { GlowingCard } from '@/components/GlowingCard'
import { Skeleton } from '@/components/ProgressLoader'
import { scaleIn, staggerContainer, staggerItem } from '@/utils/animations'

export default function PortScanner() {
  const [host, setHost] = useState('')
  const [ports, setPorts] = useState('')
  const [scanType, setScanType] = useState('quick')
  const [results, setResults] = useState<any>(null)
  const [isScanning, setIsScanning] = useState(false)

  const handleScan = async () => {
    if (!host) {
      showToast.error('Please enter a host to scan')
      return
    }

    setIsScanning(true)
    setResults(null)

    try {
      // Use Nmap scan for better results
      const response = await scanAPI.nmapScan(host, scanType)
      setResults(response.data)

      if (response.data.status === 'queued') {
        showToast.success('Scan started! Check status for results.', { duration: 5000 })
      } else {
        showToast.success('Scan completed successfully!')
      }
    } catch (error: any) {
      console.error('Scan error:', error)
      const errorMsg = error.response?.data?.detail || error.message || 'Scan failed'
      if (errorMsg.includes('limit reached')) {
        showToast.error('Monthly scan limit reached. Please upgrade your plan or wait until next month.')
      } else if (errorMsg.includes('Invalid target')) {
        showToast.error('Invalid target. Please enter a valid IP address or hostname.')
      } else {
        showToast.error(errorMsg)
      }
    } finally {
      setIsScanning(false)
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
        <h1 className="text-4xl font-bold text-white mb-2">Port Scanner</h1>
        <p className="text-gray-400">Scan network ports to discover services and potential vulnerabilities</p>
      </motion.div>

      <motion.div variants={staggerItem}>
        <GlowingCard title="Scan Configuration" accentColor="cyan">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Target Host
              </label>
              <input
                type="text"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="e.g., scanme.nmap.org or 192.168.1.1"
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 text-white"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Ports (optional, comma-separated)
              </label>
              <input
                type="text"
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                placeholder="e.g., 80,443,8080 or leave empty for common ports"
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 text-white"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Scan Type
              </label>
              <select
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 text-white"
                aria-label="Scan Type"
                title="Select scan type"
              >
                <option value="quick">Quick Scan (Top 100 ports - Fast)</option>
                <option value="full">Full Scan (All 65535 ports + Version Detection)</option>
                <option value="vuln">Vulnerability Scan (NSE Scripts)</option>
                <option value="web">Web Application Scan (HTTP/HTTPS)</option>
                <option value="stealth">Stealth Scan (SYN Stealth)</option>
                <option value="aggressive">Aggressive Scan (OS + Scripts)</option>
              </select>
            </div>

            <motion.button
              onClick={handleScan}
              disabled={isScanning}
              className="w-full py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-lg disabled:opacity-50"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              {isScanning ? 'Scanning...' : 'Start Scan'}
            </motion.button>
          </div>
        </GlowingCard>
      </motion.div>

      {isScanning && (
        <motion.div variants={scaleIn}>
          <Skeleton className="h-64" />
        </motion.div>
      )}

      {results && (
        <motion.div variants={scaleIn} initial="hidden" animate="visible">
          <GlowingCard title="Scan Results" accentColor="green">
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <p className="text-gray-400 text-sm">Target</p>
                  <p className="text-white font-semibold">{results.results?.target || results.host}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Open Ports</p>
                  <p className="text-white font-semibold">{results.results?.summary?.open_ports || results.open_ports?.length || 0}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Vulnerabilities</p>
                  <p className="text-red-400 font-semibold">{results.vulnerabilities_found || 0}</p>
                </div>
              </div>

              {results.results?.vulnerabilities && results.results.vulnerabilities.length > 0 && (
                <div className="mt-4">
                  <h4 className="text-red-400 font-semibold mb-2">⚠️ Vulnerabilities Detected:</h4>
                  <div className="space-y-2">
                    {results.results.vulnerabilities.map((vuln: any, idx: number) => (
                      <motion.div
                        key={idx}
                        initial={{ x: -20, opacity: 0 }}
                        animate={{ x: 0, opacity: 1 }}
                        transition={{ delay: idx * 0.05 }}
                        className="p-3 bg-red-900/20 rounded-lg border border-red-700"
                      >
                        <div className="flex justify-between items-start">
                          <div>
                            <span className="text-red-400 font-semibold">Port {vuln.port}</span>
                            <p className="text-gray-300 text-sm mt-1">{vuln.name}</p>
                            <p className="text-gray-400 text-xs mt-1">{vuln.description}</p>
                          </div>
                          <span className="text-xs px-2 py-1 bg-red-600 rounded">{vuln.severity}</span>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </div>
              )}

              {results.results?.ports && results.results.ports.length > 0 && (
                <div className="mt-4">
                  <h4 className="text-white font-semibold mb-2">Open Ports:</h4>
                  <div className="space-y-2">
                    {results.results.ports.map((port: any, idx: number) => (
                      <motion.div
                        key={idx}
                        initial={{ x: -20, opacity: 0 }}
                        animate={{ x: 0, opacity: 1 }}
                        transition={{ delay: idx * 0.05 }}
                        className="p-3 bg-gray-800 rounded-lg border border-gray-700"
                      >
                        <div className="flex justify-between items-center">
                          <div>
                            <span className="text-cyan-400 font-mono">Port {port.port}</span>
                            <span className="text-gray-400 ml-3">{port.service}</span>
                          </div>
                          {port.version && <span className="text-gray-500 text-sm">{port.version}</span>}
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </div>
              )}

              {results.results?.os_detection && (
                <div className="mt-4 p-3 bg-blue-900/20 rounded-lg border border-blue-700">
                  <h4 className="text-blue-400 font-semibold mb-2">OS Detection:</h4>
                  <p className="text-white">{results.results.os_detection}</p>
                </div>
              )}

              {results.nmap_available === false && (
                <div className="mt-4 p-3 bg-yellow-900/20 rounded-lg border border-yellow-700">
                  <p className="text-yellow-400 text-sm">⚠️ Nmap not installed. Using fallback Python scanner.</p>
                </div>
              )}
            </div>
          </GlowingCard>
        </motion.div>
      )}
    </motion.div>
  )
}
