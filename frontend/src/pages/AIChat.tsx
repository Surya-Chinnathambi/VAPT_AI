import { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { chatAPI } from '@/services/api'
import { showToast } from '@/components/ToastSystem'
import { PaperAirplaneIcon, ChatBubbleLeftRightIcon, TrashIcon, PlusIcon, UserIcon, CpuChipIcon } from '@heroicons/react/24/solid'
import { staggerContainer, staggerItem, slideUp } from '@/utils/animations'
import { useWebSocket } from '@/hooks/useWebSocket'

interface Message {
  role: 'user' | 'assistant'
  content: string
  timestamp?: string
}

interface Conversation {
  session_id: string
  created_at: string
  last_message_at: string
  message_count: number
  is_active: boolean
}

export default function AIChat() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [showConversations, setShowConversations] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  // WebSocket integration for real-time updates
  const { lastMessage } = useWebSocket('ws://localhost:8000/ws/chat')

  useEffect(() => {
    if (lastMessage && lastMessage.type === 'chat_response') {
      setIsLoading(false)
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: lastMessage.payload.message
      }])
    }
  }, [lastMessage])

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isLoading])

  useEffect(() => {
    loadConversations()
  }, [])

  const loadConversations = async () => {
    try {
      const response = await chatAPI.getConversations(20)
      setConversations(response.data.conversations || [])
    } catch (error) {
      console.error('Failed to load conversations:', error)
    }
  }

  const loadConversation = async (convSessionId: string) => {
    try {
      const response = await chatAPI.getConversation(convSessionId)
      setMessages(response.data.messages || [])
      setSessionId(convSessionId)
      setShowConversations(false)
      showToast.success('Conversation loaded')
    } catch (error: any) {
      showToast.error('Failed to load conversation')
    }
  }

  const startNewConversation = () => {
    setMessages([])
    setSessionId(null)
    setShowConversations(false)
    showToast.success('Started new conversation')
  }

  const deleteConversation = async (convSessionId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    try {
      await chatAPI.deleteConversation(convSessionId)
      await loadConversations()
      if (sessionId === convSessionId) {
        startNewConversation()
      }
      showToast.success('Conversation deleted')
    } catch (error) {
      showToast.error('Failed to delete conversation')
    }
  }

  const handleSend = async () => {
    if (!input.trim()) return

    const userMessage = { role: 'user' as const, content: input }
    setMessages(prev => [...prev, userMessage])
    setInput('')
    setIsLoading(true)

    try {
      const response = await chatAPI.sendMessage(input, undefined, [], sessionId || undefined)

      // If not using WebSocket for this response, handle it here
      if (response.data.message || response.data.response) {
        const assistantMessage = {
          role: 'assistant' as const,
          content: response.data.message || response.data.response
        }
        setMessages(prev => [...prev, assistantMessage])
        setIsLoading(false)
      }

      // Save session ID from first message
      if (!sessionId && response.data.session_id) {
        setSessionId(response.data.session_id)
        loadConversations() // Refresh list
      }
    } catch (error) {
      console.error('Failed to send message:', error)
      showToast.error('Failed to send message')
      setIsLoading(false)
    }
  }

  return (
    <div className="flex h-[calc(100vh-8rem)] gap-6">
      {/* Sidebar - Conversations List */}
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        className={`w-80 bg-gray-900/50 backdrop-blur-xl border border-gray-800 rounded-2xl flex flex-col overflow-hidden ${showConversations ? 'absolute inset-0 z-20 md:relative' : 'hidden md:flex'}`}
      >
        <div className="p-4 border-b border-gray-800 flex justify-between items-center">
          <h2 className="font-semibold text-gray-200">History</h2>
          <button
            onClick={startNewConversation}
            className="p-2 hover:bg-blue-600/20 text-blue-400 rounded-lg transition-colors"
            title="New Chat"
          >
            <PlusIcon className="w-5 h-5" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-2 space-y-2 scrollbar-thin scrollbar-thumb-gray-800">
          {conversations.map((conv) => (
            <motion.div
              key={conv.session_id}
              layoutId={conv.session_id}
              onClick={() => loadConversation(conv.session_id)}
              className={`p-3 rounded-xl cursor-pointer group transition-all ${sessionId === conv.session_id
                  ? 'bg-blue-600/20 border border-blue-500/30'
                  : 'hover:bg-gray-800/50 border border-transparent'
                }`}
            >
              <div className="flex justify-between items-start">
                <div className="text-sm text-gray-300 truncate w-48">
                  {new Date(conv.created_at).toLocaleDateString()}
                </div>
                <button
                  onClick={(e) => deleteConversation(conv.session_id, e)}
                  className="opacity-0 group-hover:opacity-100 text-gray-500 hover:text-red-400 transition-opacity"
                >
                  <TrashIcon className="w-4 h-4" />
                </button>
              </div>
              <div className="text-xs text-gray-500 mt-1">
                {conv.message_count} messages
              </div>
            </motion.div>
          ))}
        </div>
      </motion.div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col bg-gray-900/30 backdrop-blur-sm border border-gray-800 rounded-2xl overflow-hidden relative">
        {/* Mobile Toggle */}
        <button
          className="md:hidden absolute top-4 left-4 z-10 p-2 bg-gray-800 rounded-lg"
          onClick={() => setShowConversations(!showConversations)}
        >
          <ChatBubbleLeftRightIcon className="w-5 h-5 text-gray-400" />
        </button>

        <div className="flex-1 overflow-y-auto p-4 space-y-6 scrollbar-thin scrollbar-thumb-gray-800">
          {messages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-gray-500 space-y-4">
              <div className="w-16 h-16 bg-gray-800/50 rounded-2xl flex items-center justify-center">
                <CpuChipIcon className="w-8 h-8 text-blue-500" />
              </div>
              <p className="text-lg font-medium">How can I help you secure your system today?</p>
            </div>
          ) : (
            messages.map((msg, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className={`flex gap-4 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                {msg.role === 'assistant' && (
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center flex-shrink-0 shadow-lg shadow-blue-500/20">
                    <CpuChipIcon className="w-5 h-5 text-white" />
                  </div>
                )}

                <div className={`max-w-[80%] p-4 rounded-2xl ${msg.role === 'user'
                    ? 'bg-blue-600 text-white rounded-tr-none shadow-lg shadow-blue-600/10'
                    : 'bg-gray-800/80 text-gray-100 rounded-tl-none border border-gray-700/50'
                  }`}>
                  <p className="whitespace-pre-wrap leading-relaxed">{msg.content}</p>
                </div>

                {msg.role === 'user' && (
                  <div className="w-8 h-8 rounded-full bg-gray-700 flex items-center justify-center flex-shrink-0">
                    <UserIcon className="w-5 h-5 text-gray-300" />
                  </div>
                )}
              </motion.div>
            ))
          )}

          {isLoading && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex gap-4"
            >
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center flex-shrink-0">
                <CpuChipIcon className="w-5 h-5 text-white" />
              </div>
              <div className="bg-gray-800/80 p-4 rounded-2xl rounded-tl-none border border-gray-700/50 flex items-center gap-2">
                <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
            </motion.div>
          )}
          <div ref={messagesEndRef} />
        </div>

        <div className="p-4 bg-gray-900/50 border-t border-gray-800">
          <div className="relative flex items-center">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && handleSend()}
              placeholder="Ask about vulnerabilities, scan results, or security advice..."
              className="w-full bg-gray-950/50 border border-gray-800 rounded-xl py-4 pl-4 pr-12 text-gray-100 placeholder-gray-500 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/50 transition-all"
              disabled={isLoading}
            />
            <button
              onClick={handleSend}
              disabled={!input.trim() || isLoading}
              className="absolute right-2 p-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-colors shadow-lg shadow-blue-600/20"
            >
              <PaperAirplaneIcon className="w-5 h-5" />
            </button>
          </div>
          <div className="text-center mt-2">
            <p className="text-xs text-gray-500">AI can make mistakes. Verify important security information.</p>
          </div>
        </div>
      </div>
    </div>
  )
}
