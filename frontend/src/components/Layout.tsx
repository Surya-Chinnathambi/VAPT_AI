import { motion } from 'framer-motion'
import { Link, useLocation } from 'react-router-dom'
import { ReactNode } from 'react'
import {
  HomeIcon,
  MagnifyingGlassIcon,
  GlobeAltIcon,
  ChatBubbleBottomCenterTextIcon,
  ShieldCheckIcon,
  GlobeAmericasIcon,
  BoltIcon,
  DocumentTextIcon,
  CreditCardIcon,
  ArrowRightOnRectangleIcon
} from '@heroicons/react/24/outline'
import { AnimatedIcon } from './AnimatedIcon'
import { pageTransition } from '@/utils/animations'

interface LayoutProps {
  children: ReactNode
  setIsLoading: (loading: boolean) => void
}

const navItems = [
  { name: 'Dashboard', path: '/', icon: HomeIcon },
  { name: 'Port Scanner', path: '/port-scanner', icon: MagnifyingGlassIcon },
  { name: 'Web Scanner', path: '/web-scanner', icon: GlobeAltIcon },
  { name: 'AI Chat', path: '/ai-chat', icon: ChatBubbleBottomCenterTextIcon },
  { name: 'CVE Database', path: '/cve-database', icon: ShieldCheckIcon },
  { name: 'Shodan', path: '/shodan', icon: GlobeAmericasIcon },
  { name: 'Exploits', path: '/exploits', icon: BoltIcon },
  { name: 'Reports', path: '/reports', icon: DocumentTextIcon },
  { name: 'Billing', path: '/billing', icon: CreditCardIcon }
]

export default function Layout({ children }: LayoutProps) {
  const location = useLocation()

  const handleLogout = () => {
    localStorage.removeItem('token')
    window.location.href = '/login'
  }

  return (
    <motion.div
      className="min-h-screen bg-gray-950 flex"
      variants={pageTransition}
      initial="hidden"
      animate="visible"
      exit="exit"
    >
      <motion.aside
        initial={{ x: -300 }}
        animate={{ x: 0 }}
        className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col"
      >
        <div className="p-6">
          <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-purple-600 bg-clip-text text-transparent">
            CyberSec AI
          </h1>
        </div>

        <nav className="flex-1 px-4 space-y-1">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path
            return (
              <Link key={item.path} to={item.path}>
                <motion.div
                  className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${isActive
                      ? 'bg-blue-600 text-white'
                      : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                    }`}
                  whileHover={{ x: 4 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <item.icon className="w-5 h-5" />
                  <span className="font-medium">{item.name}</span>
                </motion.div>
              </Link>
            )
          })}
        </nav>

        <div className="p-4 border-t border-gray-800">
          <AnimatedIcon
            icon={
              <div className="flex items-center gap-3 px-4 py-3 text-gray-400 hover:text-white transition-colors">
                <ArrowRightOnRectangleIcon className="w-5 h-5" />
                <span className="font-medium">Logout</span>
              </div>
            }
            onClick={handleLogout}
            hoverEffect="pop"
            ariaLabel="Logout"
          />
        </div>
      </motion.aside>

      <main className="flex-1 overflow-auto">
        <div className="container mx-auto px-6 py-8">
          {children}
        </div>
      </main>
    </motion.div>
  )
}
