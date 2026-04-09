import { useState } from 'react'
import { useAuth } from '../hooks/useAuth'
import { api } from '../api/client'

function InputField({ label, hint, value, onChange, onKeyDown, placeholder, type = 'text' }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 6 }}>
        <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: 0.5, textTransform: 'uppercase' }}>
          {label}
        </label>
        {hint && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{hint}</span>}
      </div>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        onKeyDown={onKeyDown}
        placeholder={placeholder}
        style={{
          width: '100%', padding: '12px 16px',
          background: 'var(--bg-input)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-sm)',
          color: 'var(--text-primary)',
          fontFamily: type === 'password' ? 'var(--font)' : 'var(--font-mono)',
          fontSize: 15, outline: 'none', boxSizing: 'border-box',
        }}
        onFocus={e => e.target.style.borderColor = 'var(--border-active)'}
        onBlur={e => e.target.style.borderColor = 'var(--border)'}
      />
    </div>
  )
}

export default function LoginPage() {
  const { login, updateStudent } = useAuth()
  const [studentId, setStudentId] = useState('')
  const [password, setPassword] = useState('')
  const [portalPassword, setPortalPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // 2FA state
  const [needs2fa, setNeeds2fa] = useState(false)
  const [code2fa, setCode2fa] = useState('')

  async function handleLogin() {
    if (!studentId || !password) return
    setLoading(true)
    setError('')
    try {
      const data = await api.login(studentId, password, portalPassword)
      if (data.needs_portal_2fa) {
        // Login successful but portal needs 2FA — save student data and show 2FA form
        login(data)
        setNeeds2fa(true)
      } else {
        login(data)
      }
    } catch (e) {
      setError(e.message || 'Неверный ID или пароль')
    } finally {
      setLoading(false)
    }
  }

  async function handle2fa() {
    if (!code2fa) return
    setLoading(true)
    setError('')
    try {
      const profile = await api.verify2fa(studentId, code2fa)
      updateStudent(profile)
      // Successful — useAuth will redirect since student is already set
    } catch (e) {
      setError(e.message || 'Неверный код')
    } finally {
      setLoading(false)
    }
  }

  const canLogin = studentId && password && !loading

  return (
    <div style={{
      minHeight: '100%', overflowY: 'auto',
      display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center',
      padding: '24px 20px', background: 'var(--bg)',
    }}>
      <div style={{
        width: 72, height: 72, borderRadius: 24,
        background: 'linear-gradient(135deg, var(--accent), #7c3aed)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: 36, marginBottom: 20,
        boxShadow: 'var(--shadow-accent)',
        animation: 'fadeUp 0.4s ease',
      }}>🎓</div>

      <div style={{ textAlign: 'center', marginBottom: 28, animation: 'fadeUp 0.4s ease 0.1s both' }}>
        <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8, letterSpacing: -0.5 }}>
          SDU AI Assistant
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: 14 }}>
          {needs2fa ? 'Введи код из email/SMS' : 'Войди через свой студенческий аккаунт'}
        </p>
      </div>

      <div style={{ width: '100%', maxWidth: 360, animation: 'fadeUp 0.4s ease 0.2s both' }}>
        {!needs2fa ? (
          <>
            <InputField label="Студенческий ID" value={studentId} onChange={setStudentId} placeholder="230103237" />
            <InputField label="Пароль Moodle" hint="moodle.sdu.edu.kz" type="password" value={password} onChange={setPassword} placeholder="••••••••" />
            <div style={{ marginBottom: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: 0.5, textTransform: 'uppercase' }}>
                  Пароль Портала
                </label>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>my.sdu.edu.kz</span>
              </div>
              <input
                type="password"
                value={portalPassword}
                onChange={e => setPortalPassword(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleLogin()}
                placeholder="••••••••  (необязательно)"
                style={{
                  width: '100%', padding: '12px 16px',
                  background: 'var(--bg-input)', border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)',
                  fontFamily: 'var(--font)', fontSize: 15,
                  outline: 'none', boxSizing: 'border-box',
                }}
                onFocus={e => e.target.style.borderColor = 'var(--border-active)'}
                onBlur={e => e.target.style.borderColor = 'var(--border)'}
              />
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 5 }}>
                Нужен для загрузки фото и программы обучения
              </div>
            </div>
          </>
        ) : (
          <div style={{ marginBottom: 20 }}>
            <div style={{
              padding: '12px 14px', marginBottom: 16,
              background: 'rgba(99,102,241,0.1)',
              border: '1px solid rgba(99,102,241,0.3)',
              borderRadius: 'var(--radius-sm)',
              fontSize: 13, color: 'var(--text-secondary)',
            }}>
              📧 Портал SDU запросил подтверждение. Проверь email или SMS.
            </div>
            <InputField
              label="Код верификации"
              value={code2fa}
              onChange={setCode2fa}
              onKeyDown={e => e.key === 'Enter' && handle2fa()}
              placeholder="123456"
            />
          </div>
        )}

        {error && (
          <div style={{
            padding: '10px 14px', marginBottom: 14,
            background: 'var(--red-dim)',
            border: '1px solid rgba(248,113,113,0.3)',
            borderRadius: 'var(--radius-sm)',
            color: 'var(--red)', fontSize: 13,
          }}>
            {error}
          </div>
        )}

        <button
          onClick={needs2fa ? handle2fa : handleLogin}
          disabled={needs2fa ? (!code2fa || loading) : !canLogin}
          style={{
            width: '100%', padding: '13px',
            background: (needs2fa ? !!code2fa : canLogin) ? 'var(--accent)' : 'var(--bg-elevated)',
            border: 'none', borderRadius: 'var(--radius-sm)',
            color: 'white', fontSize: 15, fontFamily: 'var(--font)',
            fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s',
            boxShadow: (needs2fa ? !!code2fa : canLogin) ? 'var(--shadow-accent)' : 'none',
          }}
        >
          {loading ? 'Загрузка...' : needs2fa ? 'Подтвердить' : 'Войти'}
        </button>

        {needs2fa && (
          <button
            onClick={() => { setNeeds2fa(false); setCode2fa(''); setError('') }}
            style={{
              width: '100%', marginTop: 10, padding: '10px',
              background: 'transparent', border: 'none',
              color: 'var(--text-muted)', fontSize: 13,
              cursor: 'pointer', fontFamily: 'var(--font)',
            }}
          >
            ← Назад
          </button>
        )}
      </div>
    </div>
  )
}
