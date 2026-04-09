import { useState, useRef, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth'
import { api } from '../api/client'

const SUGGESTIONS = [
  'Какие у меня задания на этой неделе?',
  'Какая следующая пара?',
  'Моё расписание сегодня',
  'Какая у меня посещаемость?',
]

function Message({ msg }) {
  const isUser = msg.role === 'user'
  return (
    <div style={{
      display: 'flex',
      justifyContent: isUser ? 'flex-end' : 'flex-start',
      marginBottom: 12,
      animation: 'fadeUp 0.25s ease forwards',
    }}>
      {!isUser && (
        <div style={{
          width: 30, height: 30,
          borderRadius: '50%',
          background: 'var(--accent-dim)',
          border: '1px solid var(--border-active)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 14,
          flexShrink: 0,
          marginRight: 8,
          marginTop: 2,
        }}>🎓</div>
      )}
      <div style={{
        maxWidth: '78%',
        padding: '10px 14px',
        borderRadius: isUser ? '18px 18px 4px 18px' : '18px 18px 18px 4px',
        background: isUser ? 'var(--accent)' : 'var(--bg-elevated)',
        border: isUser ? 'none' : '1px solid var(--border)',
        color: isUser ? 'white' : 'var(--text-primary)',
        fontSize: 14,
        lineHeight: 1.55,
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
      }}>
        {msg.text}
      </div>
    </div>
  )
}

function TypingIndicator() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
      <div style={{
        width: 30, height: 30, borderRadius: '50%',
        background: 'var(--accent-dim)', border: '1px solid var(--border-active)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 14,
      }}>🎓</div>
      <div style={{
        padding: '10px 16px',
        background: 'var(--bg-elevated)',
        border: '1px solid var(--border)',
        borderRadius: '18px 18px 18px 4px',
        display: 'flex', gap: 5, alignItems: 'center',
      }}>
        {[0,1,2].map(i => (
          <span key={i} style={{
            width: 6, height: 6, borderRadius: '50%',
            background: 'var(--text-secondary)',
            display: 'block',
            animation: 'pulse 1.2s ease infinite',
            animationDelay: `${i * 0.2}s`,
          }} />
        ))}
      </div>
    </div>
  )
}

export default function ChatPage() {
  const { student } = useAuth()
  const [messages, setMessages] = useState([
    {
      id: 1,
      role: 'assistant',
      text: `Привет${student?.name ? ', ' + student.name.split(' ')[0] : ''}! 👋\n\nЯ твой академический помощник SDU. Спроси меня про расписание, задания, дедлайны или посещаемость.`,
    }
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef(null)
  const inputRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  async function send(text) {
    const msg = text || input.trim()
    if (!msg || loading) return
    setInput('')

    setMessages(prev => [...prev, { id: Date.now(), role: 'user', text: msg }])
    setLoading(true)

    try {
      const data = await api.sendMessage(msg, student?.student_id || '220103001')
      setMessages(prev => [...prev, {
        id: Date.now() + 1,
        role: 'assistant',
        text: data.response,
      }])
    } catch (e) {
      setMessages(prev => [...prev, {
        id: Date.now() + 1,
        role: 'assistant',
        text: '⚠️ Ошибка соединения с сервером. Проверь что backend запущен.',
      }])
    } finally {
      setLoading(false)
    }
  }

  function handleKey(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }

  return (
    <div className="page" style={{ display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <div className="page-header" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{
          width: 38, height: 38, borderRadius: '50%',
          background: 'linear-gradient(135deg, var(--accent), #7c3aed)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 18, boxShadow: 'var(--shadow-accent)',
        }}>🎓</div>
        <div>
          <div className="page-title" style={{ fontSize: 17 }}>SDU AI Assistant</div>
          <div className="page-subtitle" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{
              width: 6, height: 6, borderRadius: '50%',
              background: 'var(--green)', display: 'inline-block',
            }} />
            онлайн
          </div>
        </div>
      </div>

      {/* Messages */}
      <div className="scroll-area" style={{ flex: 1, padding: '16px 16px 8px' }}>
        {messages.map(msg => <Message key={msg.id} msg={msg} />)}
        {loading && <TypingIndicator />}
        <div ref={bottomRef} />
      </div>

      {/* Suggestions (show only at start) */}
      {messages.length <= 1 && !loading && (
        <div style={{
          padding: '0 16px 12px',
          display: 'flex', gap: 8, overflowX: 'auto',
          scrollbarWidth: 'none',
        }}>
          {SUGGESTIONS.map((s, i) => (
            <button
              key={i}
              onClick={() => send(s)}
              style={{
                flexShrink: 0,
                padding: '7px 12px',
                borderRadius: 20,
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border)',
                color: 'var(--text-secondary)',
                fontSize: 12.5,
                fontFamily: 'var(--font)',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
                transition: 'all 0.15s',
              }}
            >
              {s}
            </button>
          ))}
        </div>
      )}

      {/* Input */}
      <div style={{
        padding: '10px 12px',
        background: 'var(--bg-card)',
        borderTop: '1px solid var(--border)',
        display: 'flex', gap: 8, alignItems: 'flex-end',
      }}>
        <textarea
          ref={inputRef}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Напиши вопрос..."
          rows={1}
          style={{
            flex: 1,
            background: 'var(--bg-input)',
            border: '1px solid var(--border)',
            borderRadius: 22,
            padding: '10px 16px',
            color: 'var(--text-primary)',
            fontFamily: 'var(--font)',
            fontSize: 14,
            resize: 'none',
            outline: 'none',
            maxHeight: 120,
            overflowY: 'auto',
            lineHeight: 1.5,
            transition: 'border-color 0.15s',
          }}
          onFocus={e => e.target.style.borderColor = 'var(--border-active)'}
          onBlur={e => e.target.style.borderColor = 'var(--border)'}
        />
        <button
          onClick={() => send()}
          disabled={!input.trim() || loading}
          style={{
            width: 42, height: 42,
            borderRadius: '50%',
            background: input.trim() && !loading ? 'var(--accent)' : 'var(--bg-input)',
            border: 'none', cursor: input.trim() ? 'pointer' : 'default',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            transition: 'all 0.2s',
            flexShrink: 0,
            boxShadow: input.trim() ? 'var(--shadow-accent)' : 'none',
          }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
            <path d="M22 2L11 13M22 2L15 22l-4-9-9-4 20-7z"
              stroke={input.trim() && !loading ? 'white' : 'var(--text-muted)'}
              strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </button>
      </div>
    </div>
  )
}
