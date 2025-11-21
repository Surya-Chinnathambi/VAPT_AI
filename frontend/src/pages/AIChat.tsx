import { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { chatAPI } from '@/services/api'
import { showToast } from '@/components/ToastSystem'
import { PaperAirplaneIcon, ChatBubbleLeftRightIcon, TrashIcon, PlusIcon } from '@heroicons/react/24/solid'
import { staggerContainer, staggerItem, slideUp } from '@/utils/animations'

interface Message {
  role: 'user' | 'assistant'
  content: string
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

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

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
      const assistantMessage = {
        role: 'assistant' as const,
        content: response.data.message || response.data.response
      }
      setMessages(prev => [...prev, assistantMessage])

      // Save session ID from first message
      if (!sessionId && response.data.session_id) {
        setSessionId(response.data.session_id)
      }

      // Refresh conversation list
      await loadConversations()
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Failed to get response')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <motion.div
      variants={staggerContainer}
      initial="hidden"
      animate="visible"
      className="h-[calc(100vh-8rem)] flex gap-4"
    >
      {/* Conversation List Sidebar */}
      <motion.div
        variants={staggerItem}
        className={`${showConversations ? 'w-80' : 'w-16'} transition-all duration-300 flex flex-col gap-4`}
      >
        <button
          onClick={() => setShowConversations(!showConversations)}
          className="bg-gray-900/50 border border-gray-800 rounded-lg p-4 hover:bg-gray-800/50 transition-colors"
          aria-label="Toggle conversations panel"
          title="Toggle conversations panel"
        >
          <ChatBubbleLeftRightIcon className="w-6 h-6 text-blue-500 mx-auto" />
        </button>

        <button
          onClick={startNewConversation}
          className="bg-blue-600 hover:bg-blue-700 rounded-lg p-4 transition-colors"
          title="New Conversation"
        >
          <PlusIcon className="w-6 h-6 text-white mx-auto" />
        </button>

        {showConversations && (
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            className="flex-1 bg-gray-900/50 border border-gray-800 rounded-lg p-4 overflow-y-auto"
          >
            <h3 className="text-white font-semibold mb-4">Recent Chats</h3>
            <div className="space-y-2">
              {conversations.map((conv) => (
                <div
                  key={conv.session_id}
                  onClick={() => loadConversation(conv.session_id)}
                  className={`p-3 rounded-lg cursor-pointer transition-colors group ${sessionId === conv.session_id
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-800 hover:bg-gray-700 text-gray-300'
                    }`}
                >
                  <div className="flex justify-between items-start mb-1">
                    <span className="text-sm font-medium">
                      {conv.message_count} messages
                    </span>
                    <button
                      onClick={(e) => deleteConversation(conv.session_id, e)}
                      className="opacity-0 group-hover:opacity-100 transition-opacity"
                      aria-label="Delete conversation"
                      title="Delete conversation"
                    >
                      <TrashIcon className="w-4 h-4 text-red-400 hover:text-red-300" />
                    </button>
                  </div>
                  <span className="text-xs opacity-75">
                    {new Date(conv.last_message_at).toLocaleDateString()}
                  </span>
                </div>
              ))}
              {conversations.length === 0 && (
                <p className="text-gray-500 text-sm text-center py-4">
                  No conversations yet
                </p>
              )}
            </div>
          </motion.div>
        )}
      </motion.div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col">
        <motion.div variants={staggerItem} className="mb-4">
          <div className="flex justify-between items-center">
            <div>
              <h1 className="text-4xl font-bold text-white mb-2">AI Security Assistant</h1>
              <p className="text-gray-400">Get AI-powered security analysis and recommendations</p>
            </div>
            {sessionId && (
              <span className="text-xs text-gray-500 px-3 py-1 bg-gray-800 rounded-full">
                Session Active
              </span>
            )}
          </div>
        </motion.div>

        <motion.div
          variants={staggerItem}
          className="flex-1 bg-gray-900/50 rounded-lg border border-gray-800 p-4 overflow-y-auto mb-4"
        >
          {messages.length === 0 && (
            <div className="h-full flex items-center justify-center">
              <div className="text-center text-gray-500">
                <ChatBubbleLeftRightIcon className="w-16 h-16 mx-auto mb-4 opacity-50" />
                <p className="text-lg">Start a conversation with the AI Security Assistant</p>
                <p className="text-sm mt-2">Ask about vulnerabilities, security best practices, or scan analysis</p>
              </div>
            </div>
          )}

          <AnimatePresence initial={false}>
            {messages.map((msg, idx) => (
              <motion.div
                key={idx}
                variants={slideUp}
                initial="hidden"
                animate="visible"
                className={`mb-4 flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-[80%] p-4 rounded-lg ${msg.role === 'user'
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-800 text-gray-100'
                    }`}
                >
                  <p className="whitespace-pre-wrap">{msg.content}</p>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>

          {isLoading && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex justify-start"
            >
              <div className="bg-gray-800 text-gray-100 p-4 rounded-lg">
                <div className="flex gap-2">
                  <motion.div
                    className="w-2 h-2 bg-blue-500 rounded-full"
                    animate={{ y: [0, -8, 0] }}
                    transition={{ duration: 0.6, repeat: Infinity, delay: 0 }}
                  />
                  <motion.div
                    className="w-2 h-2 bg-blue-500 rounded-full"
                    animate={{ y: [0, -8, 0] }}
                    transition={{ duration: 0.6, repeat: Infinity, delay: 0.2 }}
                  />
                  <motion.div
                    className="w-2 h-2 bg-blue-500 rounded-full"
                    animate={{ y: [0, -8, 0] }}
                    transition={{ duration: 0.6, repeat: Infinity, delay: 0.4 }}
                  />
                </div>
              </div>
            </motion.div>
          )}

          <div ref={messagesEndRef} />
        </motion.div>

        <motion.div variants={staggerItem} className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && !isLoading && handleSend()}
            placeholder="Ask about security vulnerabilities, best practices, or analysis..."
            className="flex-1 px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 text-white"
            disabled={isLoading}
          />
          <motion.button
            onClick={handleSend}
            disabled={isLoading || !input.trim()}
            className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-lg disabled:opacity-50"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <PaperAirplaneIcon className="w-5 h-5" />
          </motion.button>
        </motion.div>
      </div>
    </motion.div>
  )
}
