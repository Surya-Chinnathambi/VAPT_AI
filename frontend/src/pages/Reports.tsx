import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { reportsAPI } from '@/services/api'
import { showToast } from '@/components/ToastSystem'
import { GlowingCard } from '@/components/GlowingCard'
import { Skeleton } from '@/components/ProgressLoader'
import { DocumentArrowDownIcon } from '@heroicons/react/24/outline'
import { staggerContainer, staggerItem, scaleIn } from '@/utils/animations'

export default function Reports() {
  const [reports, setReports] = useState<any[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isGenerating, setIsGenerating] = useState(false)

  useEffect(() => {
    loadReports()
  }, [])

  const loadReports = async () => {
    try {
      const response = await reportsAPI.list()
      setReports(response.data.reports || [])
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Failed to load reports')
    } finally {
      setIsLoading(false)
    }
  }

  const handleGenerateReport = async () => {
    setIsGenerating(true)
    try {
      const reportName = `Security Report ${new Date().toLocaleDateString()}`
      await reportsAPI.generate(reportName)
      showToast.success('Report generated successfully!')
      loadReports()
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Failed to generate report')
    } finally {
      setIsGenerating(false)
    }
  }

  const handleDownload = async (reportId: number, filename: string) => {
    try {
      const response = await reportsAPI.download(reportId.toString())
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', filename)
      document.body.appendChild(link)
      link.click()
      link.remove()
      showToast.success('Report downloaded successfully!')
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Failed to download report')
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
        <h1 className="text-4xl font-bold text-white mb-2">Security Reports</h1>
        <p className="text-gray-400">Generate and download comprehensive security reports</p>
      </motion.div>

      <motion.div variants={staggerItem}>
        <GlowingCard title="Generate New Report" accentColor="purple">
          <motion.button
            onClick={handleGenerateReport}
            disabled={isGenerating}
            className="w-full py-3 bg-gradient-to-r from-purple-600 to-pink-600 text-white font-semibold rounded-lg disabled:opacity-50"
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            {isGenerating ? 'Generating...' : 'Generate Security Report'}
          </motion.button>
        </GlowingCard>
      </motion.div>

      {isLoading && (
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
      )}

      {!isLoading && reports.length > 0 && (
        <motion.div variants={staggerContainer} className="space-y-4">
          <h2 className="text-2xl font-bold text-white">Your Reports</h2>
          {reports.map((report: any, idx: number) => (
            <motion.div
              key={idx}
              variants={scaleIn}
              initial="hidden"
              animate="visible"
              transition={{ delay: idx * 0.05 }}
            >
              <div className="p-6 bg-gray-900/50 rounded-lg border border-gray-800 hover:border-purple-500 transition-colors flex justify-between items-center">
                <div>
                  <h3 className="text-xl font-bold text-white mb-1">{report.name}</h3>
                  <p className="text-gray-400 text-sm">
                    Generated: {new Date(report.created_at).toLocaleString()}
                  </p>
                </div>
                <motion.button
                  onClick={() => handleDownload(report.id, report.filename)}
                  className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg flex items-center gap-2"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <DocumentArrowDownIcon className="w-5 h-5" />
                  Download
                </motion.button>
              </div>
            </motion.div>
          ))}
        </motion.div>
      )}
    </motion.div>
  )
}
