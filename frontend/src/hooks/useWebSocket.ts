import { useEffect, useRef, useState, useCallback } from 'react'
import { showToast } from '@/components/ToastSystem'

interface WebSocketMessage {
    type: string
    payload: any
}

export function useWebSocket(url: string) {
    const [isConnected, setIsConnected] = useState(false)
    const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
    const ws = useRef<WebSocket | null>(null)
    const reconnectTimeout = useRef<NodeJS.Timeout>()

    const connect = useCallback(() => {
        try {
            const token = localStorage.getItem('token')
            const wsUrl = `${url}?token=${token}`

            ws.current = new WebSocket(wsUrl)

            ws.current.onopen = () => {
                setIsConnected(true)
                console.log('WebSocket Connected')
            }

            ws.current.onclose = () => {
                setIsConnected(false)
                console.log('WebSocket Disconnected')
                // Attempt reconnect after 3 seconds
                reconnectTimeout.current = setTimeout(connect, 3000)
            }

            ws.current.onerror = (error) => {
                console.error('WebSocket Error:', error)
                ws.current?.close()
            }

            ws.current.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data)
                    setLastMessage(data)
                } catch (e) {
                    console.error('Failed to parse WebSocket message:', e)
                }
            }
        } catch (error) {
            console.error('WebSocket connection failed:', error)
        }
    }, [url])

    useEffect(() => {
        connect()

        return () => {
            if (ws.current) {
                ws.current.close()
            }
            if (reconnectTimeout.current) {
                clearTimeout(reconnectTimeout.current)
            }
        }
    }, [connect])

    const sendMessage = useCallback((message: any) => {
        if (ws.current?.readyState === WebSocket.OPEN) {
            ws.current.send(JSON.stringify(message))
        } else {
            showToast.error('WebSocket not connected')
        }
    }, [])

    return { isConnected, lastMessage, sendMessage }
}
