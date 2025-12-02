import { motion, AnimatePresence } from 'framer-motion'
import { Link, useLocation } from 'react-router-dom'
import { ReactNode, useState } from 'react'
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
  ArrowRightOnRectangleIcon,
  Bars3Icon,
  XMarkIcon
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
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)

  const handleLogout = () => {
    localStorage.removeItem('token')
    window.location.href = '/login'
  }

  const SidebarContent = () => (
    <>
      <div className="p-6 flex items-center justify-between">
        <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-purple-600 bg-clip-text text-transparent">
          CyberSec AI
        </h1>
        <button
          className="md:hidden text-gray-400 hover:text-white"
          onClick={() => setIsMobileMenuOpen(false)}
        >
          <XMarkIcon className="w-6 h-6" />
        </button>
      </div>

      <nav className="flex-1 px-4 space-y-1 overflow-y-auto scrollbar-thin scrollbar-thumb-gray-800">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path
          return (
            <Link key={item.path} to={item.path} onClick={() => setIsMobileMenuOpen(false)}>
              <motion.div
                className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 ${isActive
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30 shadow-[0_0_15px_rgba(37,99,235,0.2)]'
                    : 'text-gray-400 hover:bg-gray-800/50 hover:text-white hover:border hover:border-gray-700'
                  }`}
                whileHover={{ x: 4 }}
                whileTap={{ scale: 0.98 }}
              >
                <item.icon className={`w-5 h-5 ${isActive ? 'text-blue-400' : ''}`} />
                <span className="font-medium">{item.name}</span>
              </motion.div>
            </Link>
          )
        })}
      </nav>

      <div className="p-4 border-t border-gray-800/50 bg-gray-900/30 backdrop-blur-sm">
        <AnimatedIcon
          icon={
            <div className="flex items-center gap-3 px-4 py-3 text-gray-400 hover:text-red-400 transition-colors cursor-pointer rounded-lg hover:bg-red-500/10">
              <ArrowRightOnRectangleIcon className="w-5 h-5" />
              <span className="font-medium">Logout</span>
            </div>
          }
          onClick={handleLogout}
          hoverEffect="pop"
          ariaLabel="Logout"
        />
      </div>
    </>
  )

  return (
    <div className="min-h-screen bg-[#0a0a0a] flex text-gray-100 font-sans selection:bg-blue-500/30">
      {/* Mobile Menu Button */}
      <div className="md:hidden fixed top-4 left-4 z-50">
        <button
          onClick={() => setIsMobileMenuOpen(true)}
          className="p-2 bg-gray-900/80 backdrop-blur-md border border-gray-800 rounded-lg text-white shadow-lg"
        >
          <Bars3Icon className="w-6 h-6" />
        </button>
      </div>

      {/* Mobile Sidebar Overlay */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsMobileMenuOpen(false)}
              className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 md:hidden"
            />
            <motion.aside
              initial={{ x: -300 }}
              animate={{ x: 0 }}
              exit={{ x: -300 }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="fixed inset-y-0 left-0 w-72 bg-gray-900/95 backdrop-blur-xl border-r border-gray-800 z-50 md:hidden flex flex-col"
            >
              <SidebarContent />
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      {/* Desktop Sidebar */}
      <motion.aside
        initial={{ x: -300 }}
        animate={{ x: 0 }}
        className="hidden md:flex w-72 bg-gray-900/50 backdrop-blur-xl border-r border-gray-800 flex-col sticky top-0 h-screen"
      >
        <SidebarContent />
      </motion.aside>

      <main className="flex-1 overflow-x-hidden overflow-y-auto bg-[url('/grid-pattern.svg')] bg-fixed">
        <div className="container mx-auto px-4 md:px-8 py-8 md:py-12 max-w-7xl">
          <motion.div
            variants={pageTransition}
            initial="hidden"
            animate="visible"
            exit="exit"
          >
            {children}
          </motion.div>
        </div>
      </main>
    </div>
  )
}
