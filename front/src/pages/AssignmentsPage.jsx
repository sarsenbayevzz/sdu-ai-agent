import { useState, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth'
import { api } from '../api/client'

function DeadlineBadge({ daysLeft, submitted }) {
  if (submitted) return (
    <span style={{
      padding: '3px 8px', borderRadius: 6,
      background: 'var(--green-dim)', color: 'var(--green)',
      fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.3,
    }}>Сдано</span>
  )
  if (daysLeft === 0) return (
    <span style={{
      padding: '3px 8px', borderRadius: 6,
      background: 'var(--red-dim)', color: 'var(--red)',
      fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
    }}>Сегодня!</span>
  )
  if (daysLeft <= 2) return (
    <span style={{
      padding: '3px 8px', borderRadius: 6,
      background: 'var(--red-dim)', color: 'var(--red)',
      fontSize: 11, fontWeight: 700,
    }}>через {daysLeft} дн.</span>
  )
  if (daysLeft <= 5) return (
    <span style={{
      padding: '3px 8px', borderRadius: 6,
      background: 'var(--yellow-dim)', color: 'var(--yellow)',
      fontSize: 11, fontWeight: 700,
    }}>через {daysLeft} дн.</span>
  )
  return (
    <span style={{
      padding: '3px 8px', borderRadius: 6,
      background: 'var(--bg-elevated)', color: 'var(--text-secondary)',
      fontSize: 11, fontWeight: 600,
    }}>через {daysLeft} дн.</span>
  )
}

function AssignmentCard({ assignment, index }) {
  const urgent = !assignment.submitted && assignment.days_left <= 2
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid ${urgent ? 'rgba(248,113,113,0.3)' : 'var(--border)'}`,
      borderRadius: 'var(--radius)',
      padding: '14px 16px',
      marginBottom: 10,
      animation: `fadeUp 0.3s ease ${index * 0.05}s both`,
      opacity: assignment.submitted ? 0.6 : 1,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
        <div style={{ flex: 1, marginRight: 10 }}>
          <div style={{
            fontSize: 14, fontWeight: 600, color: 'var(--text-primary)',
            marginBottom: 3,
            textDecoration: assignment.submitted ? 'line-through' : 'none',
          }}>
            {assignment.title}
          </div>
          <div style={{ fontSize: 12.5, color: 'var(--accent)', fontWeight: 500 }}>
            {assignment.course_name}
          </div>
        </div>
        <DeadlineBadge daysLeft={assignment.days_left} submitted={assignment.submitted} />
      </div>

      <div style={{
        display: 'flex', alignItems: 'center', gap: 6,
        fontSize: 12, color: 'var(--text-muted)',
        fontFamily: 'var(--font-mono)',
      }}>
        <span>📅</span>
        <span>{assignment.deadline_formatted}</span>
      </div>
    </div>
  )
}

export default function AssignmentsPage() {
  const { student } = useAuth()
  const [data, setData] = useState(null)
  const [filter, setFilter] = useState('pending') // pending | all
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!student?.student_id) return
    setData(null)
    setLoading(true)
    async function load() {
      try {
        const res = await api.getAssignments(student.student_id, 30)
        setData(res)
      } catch (e) {
        console.error(e)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [student?.student_id])

  const allAssignments = data?.assignments || []
  const shown = filter === 'pending'
    ? allAssignments.filter(a => !a.submitted)
    : allAssignments

  const pendingCount = allAssignments.filter(a => !a.submitted).length
  const urgentCount = allAssignments.filter(a => !a.submitted && a.days_left <= 2).length

  return (
    <div className="page">
      <div className="page-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div className="page-title">Задания</div>
            <div className="page-subtitle">Ближайшие 30 дней</div>
          </div>
          {urgentCount > 0 && (
            <div style={{
              padding: '4px 10px',
              background: 'var(--red-dim)',
              border: '1px solid rgba(248,113,113,0.3)',
              borderRadius: 8,
              fontSize: 12, fontWeight: 700,
              color: 'var(--red)',
            }}>
              ⚡ {urgentCount} срочно
            </div>
          )}
        </div>
      </div>

      <div className="scroll-area" style={{ flex: 1 }}>
        {/* Stats row */}
        {data && (
          <div style={{
            display: 'flex', gap: 10,
            padding: '12px 16px 8px',
            animation: 'fadeUp 0.3s ease',
          }}>
            {[
              { label: 'Всего', value: allAssignments.length, color: 'var(--accent)' },
              { label: 'Не сдано', value: pendingCount, color: 'var(--yellow)' },
              { label: 'Сдано', value: allAssignments.length - pendingCount, color: 'var(--green)' },
            ].map(s => (
              <div key={s.label} style={{
                flex: 1,
                background: 'var(--bg-card)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                padding: '10px 8px',
                textAlign: 'center',
              }}>
                <div style={{ fontSize: 20, fontWeight: 700, color: s.color, fontFamily: 'var(--font-mono)' }}>
                  {s.value}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{s.label}</div>
              </div>
            ))}
          </div>
        )}

        {/* Filter tabs */}
        <div style={{ display: 'flex', gap: 8, padding: '4px 16px 12px' }}>
          {[
            { key: 'pending', label: 'Не сдано' },
            { key: 'all', label: 'Все' },
          ].map(f => (
            <button
              key={f.key}
              onClick={() => setFilter(f.key)}
              style={{
                padding: '6px 14px',
                borderRadius: 20,
                background: filter === f.key ? 'var(--accent)' : 'var(--bg-card)',
                border: `1px solid ${filter === f.key ? 'var(--accent)' : 'var(--border)'}`,
                color: filter === f.key ? 'white' : 'var(--text-secondary)',
                fontSize: 13, fontFamily: 'var(--font)',
                cursor: 'pointer', fontWeight: 500,
                transition: 'all 0.15s',
              }}
            >
              {f.label}
            </button>
          ))}
        </div>

        {/* List */}
        <div style={{ padding: '0 16px 16px' }}>
          {loading ? (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>
              Загрузка...
            </div>
          ) : shown.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '48px 20px', color: 'var(--text-secondary)', fontSize: 14 }}>
              <div style={{ fontSize: 36, marginBottom: 10 }}>✅</div>
              Всё сдано — отлично!
            </div>
          ) : (
            shown.map((a, i) => <AssignmentCard key={a.title + i} assignment={a} index={i} />)
          )}
        </div>
      </div>
    </div>
  )
}
