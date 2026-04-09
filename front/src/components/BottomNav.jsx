import { useLocation, useNavigate } from 'react-router-dom'

const TABS = [
  {
    path: '/chat',
    label: 'Чат',
    icon: (active) => (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"
          stroke={active ? 'var(--accent)' : 'var(--text-muted)'}
          strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
          fill={active ? 'var(--accent-dim)' : 'none'} />
      </svg>
    ),
  },
  {
    path: '/schedule',
    label: 'Расписание',
    icon: (active) => (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
        <rect x="3" y="4" width="18" height="18" rx="2" ry="2"
          stroke={active ? 'var(--accent)' : 'var(--text-muted)'}
          strokeWidth="2" fill={active ? 'var(--accent-dim)' : 'none'} />
        <line x1="16" y1="2" x2="16" y2="6" stroke={active ? 'var(--accent)' : 'var(--text-muted)'} strokeWidth="2" strokeLinecap="round"/>
        <line x1="8" y1="2" x2="8" y2="6" stroke={active ? 'var(--accent)' : 'var(--text-muted)'} strokeWidth="2" strokeLinecap="round"/>
        <line x1="3" y1="10" x2="21" y2="10" stroke={active ? 'var(--accent)' : 'var(--text-muted)'} strokeWidth="2"/>
      </svg>
    ),
  },
  {
    path: '/assignments',
    label: 'Задания',
    icon: (active) => (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
        <path d="M9 11l3 3L22 4" stroke={active ? 'var(--accent)' : 'var(--text-muted)'}
          strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
        <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"
          stroke={active ? 'var(--accent)' : 'var(--text-muted)'}
          strokeWidth="2" strokeLinecap="round" fill={active ? 'var(--accent-dim)' : 'none'} />
      </svg>
    ),
  },
  {
    path: '/attendance',
    label: 'Посещ.',
    icon: (active) => (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"
          stroke={active ? 'var(--accent)' : 'var(--text-muted)'}
          strokeWidth="2" strokeLinecap="round" fill={active ? 'var(--accent-dim)' : 'none'} />
        <circle cx="9" cy="7" r="4" stroke={active ? 'var(--accent)' : 'var(--text-muted)'} strokeWidth="2" fill={active ? 'var(--accent-dim)' : 'none'} />
        <path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"
          stroke={active ? 'var(--accent)' : 'var(--text-muted)'} strokeWidth="2" strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    path: '/profile',
    label: 'Профиль',
    icon: (active) => (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
        <circle cx="12" cy="8" r="4"
          stroke={active ? 'var(--accent)' : 'var(--text-muted)'}
          strokeWidth="2" fill={active ? 'var(--accent-dim)' : 'none'} />
        <path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"
          stroke={active ? 'var(--accent)' : 'var(--text-muted)'}
          strokeWidth="2" strokeLinecap="round" fill={active ? 'var(--accent-dim)' : 'none'} />
      </svg>
    ),
  },
]

export default function BottomNav() {
  const location = useLocation()
  const navigate = useNavigate()

  return (
    <nav style={{
      position: 'fixed',
      bottom: 0,
      left: 0,
      right: 0,
      height: 'var(--nav-height)',
      background: 'var(--bg-card)',
      borderTop: '1px solid var(--border)',
      display: 'flex',
      zIndex: 100,
      paddingBottom: 'env(safe-area-inset-bottom)',
    }}>
      {TABS.map((tab) => {
        const active = location.pathname === tab.path
        return (
          <button
            key={tab.path}
            onClick={() => navigate(tab.path)}
            style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 4,
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              padding: '6px 0 2px',
              transition: 'opacity 0.15s',
            }}
          >
            {tab.icon(active)}
            <span style={{
              fontSize: 10,
              fontFamily: 'var(--font)',
              fontWeight: active ? 600 : 400,
              color: active ? 'var(--accent)' : 'var(--text-muted)',
              letterSpacing: '0.2px',
              transition: 'color 0.15s',
            }}>
              {tab.label}
            </span>
          </button>
        )
      })}
    </nav>
  )
}
