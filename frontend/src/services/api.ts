import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: `${API_URL}/api`,
  headers: {
    'Content-Type': 'application/json'
  }
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export const authAPI = {
  login: (username: string, password: string) =>
    api.post('/auth/login', { username, password }),
  register: (username: string, email: string, password: string) =>
    api.post('/auth/register', { username, email, password }),
  getMe: () => api.get('/auth/me'),
  getUsage: () => api.get('/auth/usage')
}

export const scanAPI = {
  portScan: (target: string, ports?: string, scan_type?: string) =>
    api.post('/scan/port', { target, ports, scan_type }),
  nmapScan: (target: string, scan_type: string = 'quick', async_mode: boolean = true) =>
    api.post('/scan/nmap', { target, scan_type, async_mode }),
  webScan: (url: string, options?: any) =>
    api.post('/scan/web', { url, ...options }),
  getHistory: (limit = 10) =>
    api.get(`/scan/history?limit=${limit}`),
  getResult: (scanId: number) =>
    api.get(`/scan/result/${scanId}`),
  getScanStatus: (scanId: string) =>
    api.get(`/scan/status/${scanId}`),
  getStats: () =>
    api.get('/scan/stats')
}

export const chatAPI = {
  sendMessage: (message: string, context?: string, history?: any[], session_id?: string) =>
    api.post('/chat/message', { message, context, history, session_id }),
  analyzeScan: (scan_type: string, results: any) =>
    api.post('/chat/analyze', { scan_type, results }),
  getConversations: (limit = 10) =>
    api.get(`/chat/conversations?limit=${limit}`),
  getConversation: (sessionId: string) =>
    api.get(`/chat/conversation/${sessionId}`),
  deleteConversation: (sessionId: string) =>
    api.delete(`/chat/conversation/${sessionId}`)
}

export const dashboardAPI = {
  getStats: () => api.get('/dashboard/stats'),
  getActivity: () => api.get('/dashboard/activity'),
  getVulnDistribution: () => api.get('/dashboard/vulnerability-distribution')
}

export const cveAPI = {
  search: (query: string, limit = 20, page = 1) =>
    api.get(`/cve/search?query=${encodeURIComponent(query)}&limit=${limit}&page=${page}`),
  aiSearch: (query: string, limit = 20) =>
    api.get(`/cve/ai-search?query=${encodeURIComponent(query)}&limit=${limit}`),
  getRecent: (days = 7, limit = 50) =>
    api.get(`/cve/recent?days=${days}&limit=${limit}`),
  getDetails: (cveId: string) =>
    api.get(`/cve/details/${cveId}`)
}

export const shodanAPI = {
  search: (query: string, limit = 100) =>
    api.get(`/shodan/search?query=${query}&limit=${limit}`),
  getHost: (ip: string) =>
    api.get(`/shodan/host/${ip}`),
  getAPIInfo: () =>
    api.get('/shodan/api-info')
}

export const exploitsAPI = {
  search: (query: string, exploit_type?: string, platform?: string, limit = 50) =>
    api.get(`/exploits/search?query=${encodeURIComponent(query)}&exploit_type=${exploit_type || ''}&platform=${platform || ''}&limit=${limit}`),
  getByCVE: (cveId: string) =>
    api.get(`/exploits/by-cve/${cveId}`),
  getDetails: (exploitId: string) =>
    api.get(`/exploits/details/${exploitId}`)
}

export const billingAPI = {
  getPlans: () => api.get('/billing/plans'),
  getSubscription: () => api.get('/billing/subscription'),
  createCheckout: (priceId: string) =>
    api.post('/billing/create-checkout', { price_id: priceId })
}

export const reportsAPI = {
  generate: (scanId: string, reportType: string = 'pdf') =>
    api.post('/reports/generate', { scan_id: scanId, report_type: reportType }),
  list: () => api.get('/reports/list'),
  download: (reportId: string) =>
    api.get(`/reports/download/${reportId}`, { responseType: 'blob' })
}

export const complianceAPI = {
  getFrameworks: () => api.get('/compliance/frameworks'),
  getFramework: (frameworkCode: string) =>
    api.get(`/compliance/frameworks/${frameworkCode}`),
  mapVulnerabilities: (framework: string, vulnerabilities: any[]) =>
    api.post('/compliance/map', { framework, vulnerabilities }),
  assessCompliance: (framework: string, scanResults: any) =>
    api.post('/compliance/assess', { framework, scan_results: scanResults })
}

export const realtimeVAPTAPI = {
  getTools: () => api.get('/realtime/tools'),
  getStats: () => api.get('/realtime/stats'),
  quickScan: (target: string) =>
    api.post(`/realtime/quick-scan?target=${encodeURIComponent(target)}`),
  fullScan: (target: string) =>
    api.post(`/realtime/full-scan?target=${encodeURIComponent(target)}`),
  customScan: (target: string, tools: string[], scanType: string = 'standard', parallel: boolean = true, maxParallel: number = 5) =>
    api.post('/realtime/scan', { target, tools, scan_type: scanType, parallel, max_parallel: maxParallel })
}

// WebSocket helper for real-time VAPT scans
export const createRealtimeWebSocket = (scanId: string, onMessage: (data: any) => void) => {
  const wsUrl = API_URL.replace('http', 'ws')
  const ws = new WebSocket(`${wsUrl}/api/realtime/stream/${scanId}`)

  ws.onopen = () => {
    console.log('WebSocket connected')
  }

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data)
      onMessage(data)
    } catch (error) {
      console.error('Failed to parse WebSocket message:', error)
    }
  }

  ws.onerror = (error) => {
    console.error('WebSocket error:', error)
  }

  ws.onclose = () => {
    console.log('WebSocket disconnected')
  }

  return ws
}

export default api
