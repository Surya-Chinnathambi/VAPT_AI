import { useState } from 'react'
import { motion } from 'framer-motion'
import { shodanAPI } from '@/services/api'
import { showToast } from '@/components/ToastSystem'
import { GlowingCard } from '@/components/GlowingCard'
import { Skeleton } from '@/components/ProgressLoader'
import { staggerContainer, staggerItem, scaleIn } from '@/utils/animations'

export default function ShodanIntelligence() {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<any[]>([])
  const [isSearching, setIsSearching] = useState(false)

  const handleSearch = async () => {
    if (!query.trim()) {
      showToast.error('Please enter a search query')
      return
    }

    setIsSearching(true)
    setResults([])
    try {
      const response = await shodanAPI.search(query)
      const matches = response.data.matches || []
      setResults(matches)
      if (matches.length === 0) {
        showToast.info('No results found. Try a different search query.')
      } else {
        showToast.success(`Found ${response.data.total || matches.length} results`)
      }
    } catch (error: any) {
      console.error('Shodan search error:', error)
      const errorMsg = error.response?.data?.detail || error.message || 'Search failed'
      if (errorMsg.includes('not configured')) {
        showToast.error('Shodan API key not configured. Please contact administrator.')
      } else if (errorMsg.includes('API key')) {
        showToast.error('Invalid Shodan API key. Please check configuration.')
      } else if (errorMsg.includes('denied')) {
        showToast.error('Shodan API access denied. API key may need upgrading.')
      } else {
        showToast.error(errorMsg)
      }
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
        <h1 className="text-4xl font-bold text-white mb-2">Shodan Intelligence</h1>
        <p className="text-gray-400">Search for internet-connected devices and services</p>
      </motion.div>

      <motion.div variants={staggerItem}>
        <GlowingCard title="Search Shodan" accentColor="cyan">
          <div className="space-y-4">
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
              placeholder="e.g., apache, nginx, port:22..."
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-cyan-500 text-white"
            />
            <motion.button
              onClick={handleSearch}
              disabled={isSearching}
              className="w-full py-3 bg-gradient-to-r from-cyan-600 to-blue-600 text-white font-semibold rounded-lg disabled:opacity-50"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              {isSearching ? 'Searching...' : 'Search Shodan'}
            </motion.button>
          </div>
        </GlowingCard>
      </motion.div>

      {isSearching && (
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-40" />
          ))}
        </div>
      )}

      {!isSearching && results.length > 0 && (
        <motion.div variants={staggerContainer} className="space-y-4">
          {results.map((result: any, idx: number) => (
            <motion.div
              key={idx}
              variants={scaleIn}
              initial="hidden"
              animate="visible"
              transition={{ delay: idx * 0.05 }}
            >
              <div className="p-6 bg-gray-900/50 rounded-lg border border-gray-800 hover:border-cyan-500 transition-colors">
                <div className="flex justify-between items-start mb-3">
                  <h3 className="text-xl font-bold text-cyan-400">{result.ip_str}</h3>
                  <span className="px-3 py-1 bg-cyan-900/30 text-cyan-400 rounded-full text-sm">
                    Port: {result.port}
                  </span>
                </div>
                <div className="space-y-2 text-sm">
                  <p className="text-gray-300">{result.data}</p>
                  {result.org && <p className="text-gray-500">Org: {result.org}</p>}
                  {result.location && (
                    <p className="text-gray-500">
                      Location: {result.location.city}, {result.location.country_name}
                    </p>
                  )}
                </div>
              </div>
            </motion.div>
          ))}
        </motion.div>
      )}
    </motion.div>
  )
}
