import { useAuth } from '../hooks/useAuth'
import { useNavigate } from 'react-router-dom'
import { useState } from 'react'

function InfoRow({ label, value }) {
  if (!value) return null
  return (
    <div style={{
      display: 'flex', justifyContent: 'space-between',
      alignItems: 'flex-start', gap: 12,
      padding: '11px 0',
      borderBottom: '1px solid var(--border)',
    }}>
      <span style={{ fontSize: 13, color: 'var(--text-secondary)', flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 500, textAlign: 'right' }}>{value}</span>
    </div>
  )
}

export default function ProfilePage() {
  const { student, logout } = useAuth()
  const navigate = useNavigate()
  const [showConfirm, setShowConfirm] = useState(false)

  function handleLogout() {
    logout()
    navigate('/')
  }

  // Use portal photo if available, otherwise Moodle avatar
  const photoUrl = student?.portal_photo_url || student?.avatar || ''
  const initials = student?.firstname?.[0] + (student?.lastname?.[0] || '')

  return (
    <div className="page">
      <div className="page-header">
        <div className="page-title">Профиль</div>
        <div className="page-subtitle">Информация о студенте</div>
      </div>

      <div className="scroll-area" style={{ flex: 1 }}>
        {/* Avatar + name */}
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          padding: '28px 20px 20px',
          animation: 'fadeUp 0.3s ease',
        }}>
          {photoUrl ? (
            <img
              src={photoUrl}
              alt="Student photo"
              style={{
                width: 90, height: 90, borderRadius: '50%',
                objectFit: 'cover',
                border: '3px solid var(--border-active)',
                boxShadow: 'var(--shadow-accent)',
              }}
              onError={e => { e.target.style.display = 'none' }}
            />
          ) : (
            <div style={{
              width: 90, height: 90, borderRadius: '50%',
              background: 'linear-gradient(135deg, var(--accent), #7c3aed)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 28, fontWeight: 700, color: 'white',
              boxShadow: 'var(--shadow-accent)',
            }}>
              {initials || '?'}
            </div>
          )}

          <div style={{ marginTop: 14, textAlign: 'center' }}>
            <div style={{ fontSize: 18, fontWeight: 700, letterSpacing: -0.3 }}>
              {student?.name}
            </div>
            {student?.fullname_native && (
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 3 }}>
                {student.fullname_native}
              </div>
            )}
            <div style={{
              marginTop: 8,
              display: 'inline-flex', alignItems: 'center', gap: 5,
              padding: '4px 12px', borderRadius: 20,
              background: 'var(--green-dim)',
              border: '1px solid rgba(52,211,153,0.3)',
            }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--green)', display: 'block' }} />
              <span style={{ fontSize: 12, color: 'var(--green)', fontWeight: 600 }}>
                {student?.status || 'Studying'}
              </span>
            </div>
          </div>
        </div>

        {/* Info card */}
        <div style={{ margin: '0 16px', animation: 'fadeUp 0.3s ease 0.1s both' }}>
          <div className="card">
            <InfoRow label="Student ID" value={student?.student_id} />
            <InfoRow label="Программа" value={student?.program} />
            <InfoRow label="Advisor" value={student?.advisor} />
            <InfoRow label="Email" value={student?.email} />
            <InfoRow label="Дата рождения" value={student?.birth_date} />
            <InfoRow label="Грант" value={student?.grant_type} />
          </div>
        </div>

        {/* Logout button */}
        <div style={{ padding: '20px 16px', animation: 'fadeUp 0.3s ease 0.2s both' }}>
          {!showConfirm ? (
            <button
              onClick={() => setShowConfirm(true)}
              style={{
                width: '100%', padding: '13px',
                background: 'var(--red-dim)',
                border: '1px solid rgba(248,113,113,0.3)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--red)', fontSize: 15,
                fontFamily: 'var(--font)', fontWeight: 600,
                cursor: 'pointer', transition: 'all 0.15s',
              }}
            >
              Выйти из аккаунта
            </button>
          ) : (
            <div style={{
              background: 'var(--bg-card)',
              border: '1px solid rgba(248,113,113,0.3)',
              borderRadius: 'var(--radius)',
              padding: '16px',
              textAlign: 'center',
            }}>
              <div style={{ fontSize: 14, color: 'var(--text-primary)', marginBottom: 14 }}>
                Точно хочешь выйти?
              </div>
              <div style={{ display: 'flex', gap: 10 }}>
                <button
                  onClick={() => setShowConfirm(false)}
                  style={{
                    flex: 1, padding: '10px',
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-sm)',
                    color: 'var(--text-secondary)',
                    fontFamily: 'var(--font)', fontSize: 14,
                    cursor: 'pointer',
                  }}
                >
                  Отмена
                </button>
                <button
                  onClick={handleLogout}
                  style={{
                    flex: 1, padding: '10px',
                    background: 'var(--red)',
                    border: 'none',
                    borderRadius: 'var(--radius-sm)',
                    color: 'white',
                    fontFamily: 'var(--font)', fontSize: 14,
                    fontWeight: 600, cursor: 'pointer',
                  }}
                >
                  Выйти
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
