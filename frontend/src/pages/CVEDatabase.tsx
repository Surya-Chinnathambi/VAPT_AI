import { useState } from 'react'
import { motion } from 'framer-motion'
import { cveAPI } from '@/services/api'
import { showToast } from '@/components/ToastSystem'
import { GlowingCard } from '@/components/GlowingCard'
import { Skeleton } from '@/components/ProgressLoader'
import { MagnifyingGlassIcon, SparklesIcon, ClockIcon } from '@heroicons/react/24/outline'
import { staggerContainer, staggerItem, scaleIn } from '@/utils/animations'

export default function CVEDatabase() {
  const [keyword, setKeyword] = useState('')
  const [results, setResults] = useState<any[]>([])
  const [isSearching, setIsSearching] = useState(false)
  const [searchMode, setSearchMode] = useState<'normal' | 'ai' | 'recent'>('normal')
  const [aiSummary, setAiSummary] = useState('')

  const handleSearch = async () => {
    if (!keyword.trim() && searchMode !== 'recent') {
      showToast.error('Please enter a search keyword')
      return
    }

    setIsSearching(true)
    setAiSummary('')

    try {
      let response
      if (searchMode === 'ai') {
        response = await cveAPI.aiSearch(keyword)
        setAiSummary(response.data.ai_summary || '')
        setResults(response.data.cves || [])
        showToast.success(`AI found ${response.data.total || 0} CVEs for "${response.data.search_keywords}"`)
      } else if (searchMode === 'recent') {
        response = await cveAPI.getRecent()
        setResults(response.data.cves || [])
        showToast.success(`Found ${response.data.total || 0} recent CVEs`)
      } else {
        response = await cveAPI.search(keyword, 20)
        setResults(response.data.cves || [])
        showToast.success(`Found ${response.data.cves?.length || 0} CVEs`)
      }
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Search failed')
    } finally {
      setIsSearching(false)
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
        <h1 className="text-4xl font-bold text-white mb-2">CVE Database</h1>
        <p className="text-gray-400">Real-time CVE search with AI assistance and ExploitDB links</p>
      </motion.div>

      <motion.div variants={staggerItem}>
        <GlowingCard title="Search CVEs" accentColor="green">
          <div className="space-y-4">
            <div className="flex gap-2 mb-4">
              <button
                onClick={() => setSearchMode('normal')}
                className={`px-4 py-2 rounded-lg font-medium transition ${searchMode === 'normal'
                  ? 'bg-green-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                  }`}
              >
                <MagnifyingGlassIcon className="w-4 h-4 inline mr-2" />
                Normal Search
              </button>
              <button
                onClick={() => setSearchMode('ai')}
                className={`px-4 py-2 rounded-lg font-medium transition ${searchMode === 'ai'
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                  }`}
              >
                <SparklesIcon className="w-4 h-4 inline mr-2" />
                AI Search
              </button>
              <button
                onClick={() => {
                  setSearchMode('recent')
                  handleSearch()
                }}
                className={`px-4 py-2 rounded-lg font-medium transition ${searchMode === 'recent'
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                  }`}
              >
                <ClockIcon className="w-4 h-4 inline mr-2" />
                Recent CVEs
              </button>
            </div>

            {searchMode !== 'recent' && (
              <div className="flex gap-2">
                <input
                  type="text"
                  value={keyword}
                  onChange={(e) => setKeyword(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                  placeholder={
                    searchMode === 'ai'
                      ? 'Ask AI: "CVE for Apache server" or "WordPress vulnerabilities"'
                      : 'Search by CVE ID, product, vendor...'
                  }
                  className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-green-500 text-white"
                />
                <motion.button
                  onClick={handleSearch}
                  disabled={isSearching}
                  className={`px-6 py-2 font-semibold rounded-lg disabled:opacity-50 flex items-center gap-2 ${searchMode === 'ai'
                    ? 'bg-gradient-to-r from-purple-600 to-pink-600'
                    : 'bg-gradient-to-r from-green-600 to-emerald-600'
                    } text-white`}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  {searchMode === 'ai' ? <SparklesIcon className="w-5 h-5" /> : <MagnifyingGlassIcon className="w-5 h-5" />}
                  Search
                </motion.button>
              </div>
            )}
          </div>
        </GlowingCard>
      </motion.div>

      {aiSummary && (
        <motion.div variants={scaleIn} initial="hidden" animate="visible">
          <GlowingCard title="🤖 AI Analysis" accentColor="purple">
            <p className="text-gray-300">{aiSummary}</p>
          </GlowingCard>
        </motion.div>
      )}

      {isSearching && (
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-32" />
          ))}
        </div>
      )}

      {!isSearching && results.length > 0 && (
        <motion.div variants={staggerContainer} className="space-y-4">
          {results.map((cve: any, idx: number) => (
            <motion.div
              key={idx}
              variants={scaleIn}
              initial="hidden"
              animate="visible"
              transition={{ delay: idx * 0.05 }}
            >
              <div className="p-6 bg-gray-900/50 rounded-lg border border-gray-800 hover:border-green-500 transition-colors">
                <div className="flex justify-between items-start mb-3">
                  <div>
                    <h3 className="text-xl font-bold text-green-400">{cve.cve_id}</h3>
                    {cve.exploits_available && (
                      <span className="inline-flex items-center gap-1 mt-1 px-2 py-1 bg-red-900/30 text-red-400 rounded text-xs font-medium">
                        ⚠️ {cve.exploit_count || 0} Exploit(s) Available
                      </span>
                    )}
                  </div>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${cve.severity === 'CRITICAL' ? 'bg-red-900/30 text-red-400' :
                    cve.severity === 'HIGH' ? 'bg-orange-900/30 text-orange-400' :
                      cve.severity === 'MEDIUM' ? 'bg-yellow-900/30 text-yellow-400' :
                        'bg-blue-900/30 text-blue-400'
                    }`}>
                    {cve.severity || 'UNKNOWN'} ({cve.cvss_score || 'N/A'})
                  </span>
                </div>
                <p className="text-gray-300 mb-3">{cve.description}</p>

                {cve.exploits && cve.exploits.length > 0 && (
                  <div className="mt-3 p-3 bg-red-900/10 border border-red-800 rounded">
                    <p className="text-red-400 font-semibold mb-2">🔴 Linked Exploits:</p>
                    {cve.exploits.map((exploit: any, i: number) => (
                      <div key={i} className="text-sm text-gray-400 ml-4">
                        • {exploit.title} ({exploit.platform})
                        {exploit.edb_id && (
                          <a
                            href={`https://www.exploit-db.com/exploits/${exploit.edb_id.replace('EDB-', '')}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="ml-2 text-blue-400 hover:text-blue-300"
                          >
                            View on ExploitDB →
                          </a>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                <div className="flex gap-4 text-sm text-gray-500 mt-3">
                  <span>Published: {new Date(cve.published_date).toLocaleDateString() || 'N/A'}</span>
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-green-400 hover:text-green-300"
                  >
                    View on NVD →
                  </a>
                </div>
              </div>
            </motion.div>
          ))}
        </motion.div>
      )}
    </motion.div>
  )
}
