import { useEffect, useRef, useCallback } from 'react'
import { useNexusStore } from '../store/nexusStore'
import { WS_URL } from '../api/client'

export function useNexusWebSocket() {
  const wsRef   = useRef(null)
  const retryRef = useRef(0)
  const { addLog, setWsConnected, addNotification } = useNexusStore()

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(`${WS_URL}/ws/logs`)
      wsRef.current = ws
      ws.onopen  = () => { retryRef.current = 0; setWsConnected(true) }
      ws.onmessage = (evt) => {
        try {
          const d = JSON.parse(evt.data)
          if (d.type === 'log' || d.level) {
            addLog({ level:(d.level||'INFO').toUpperCase(), source:d.source||'nexus', msg:d.message||d.msg||'', ts:new Date(d.timestamp||Date.now()) })
          }
        } catch {
          addLog({ level:'DEBUG', source:'ws', msg:evt.data, ts:new Date() })
        }
      }
      ws.onerror  = () => setWsConnected(false)
      ws.onclose  = () => {
        setWsConnected(false)
        setTimeout(connect, Math.min(1000 * 2 ** retryRef.current++, 15000))
      }
    } catch(e) { console.error('WS logs error:', e) }
  }, [])

  useEffect(() => { connect(); return () => wsRef.current?.close() }, [connect])
}

export function useHITLWebSocket() {
  const wsRef   = useRef(null)
  const retryRef = useRef(0)
  const { addHITL, resolveHITL, setWsHITL, addNotification, setHITL } = useNexusStore()

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(`${WS_URL}/ws/hitl`)
      wsRef.current = ws
      ws.onopen  = () => { retryRef.current = 0; setWsHITL(true) }
      ws.onmessage = (evt) => {
        try {
          const d = JSON.parse(evt.data)
          if (d.event === 'connected') {
            setHITL(d.data?.pending || [])
          } else if (d.event === 'new_request') {
            addHITL(d.data)
            addNotification(`⏸ HITL: ${d.data.agent_name} → ${d.data.tool} [${d.data.risk}]`, 'warn')
          } else if (d.event === 'approved') {
            resolveHITL(d.data.id)
            addNotification(`✓ HITL aprobado: ${d.data.id}`, 'success')
          } else if (d.event === 'denied') {
            resolveHITL(d.data.id)
            addNotification(`✗ HITL denegado: ${d.data.id}`, 'error')
          } else if (d.event === 'timeout') {
            resolveHITL(d.data.id)
            addNotification(`⏰ HITL timeout: ${d.data.id}`, 'warn')
          }
        } catch(e) { console.error('HITL WS parse error:', e) }
      }
      ws.onerror  = () => setWsHITL(false)
      ws.onclose  = () => {
        setWsHITL(false)
        setTimeout(connect, Math.min(1000 * 2 ** retryRef.current++, 15000))
      }
    } catch(e) { console.error('WS HITL error:', e) }
  }, [])

  useEffect(() => { connect(); return () => wsRef.current?.close() }, [connect])

  const sendCommand = useCallback((cmd) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(cmd))
    }
  }, [])

  return { sendCommand }
}
