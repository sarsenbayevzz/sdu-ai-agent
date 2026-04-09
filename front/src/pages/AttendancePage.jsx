import { useState, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth'
import { api } from '../api/client'

function CircleProgress({ percentage, size = 64, strokeWidth = 5 }) {
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (percentage / 100) * circumference
  const color = percentage >= 75 ? 'var(--green)' : percentage >= 50 ? 'var(--yellow)' : 'var(--red)'

  return (
    <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={size/2} cy={size/2} r={radius}
          fill="none" stroke="var(--bg-elevated)" strokeWidth={strokeWidth} />
        <circle cx={size/2} cy={size/2} r={radius}
          fill="none" stroke={color} strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.8s ease' }}
        />
      </svg>
      <div style={{
        position: 'absolute', inset: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: 11, fontWeight: 700, fontFamily: 'var(--font-mono)',
        color,
      }}>
        {Math.round(percentage)}%
      </div>
    </div>
  )
}

function AttendanceCard({ course, index }) {
  const statusMap = {
    ok: { color: 'var(--green)', label: 'Хорошо', bg: 'var(--green-dim)' },
    warning: { color: 'var(--yellow)', label: 'Внимание', bg: 'var(--yellow-dim)' },
    critical: { color: 'var(--red)', label: 'Критично', bg: 'var(--red-dim)' },
  }
  const s = statusMap[course.status]

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid ${course.status !== 'ok' ? s.color + '44' : 'var(--border)'}`,
      borderRadius: 'var(--radius)',
      padding: '14px 16px',
      marginBottom: 10,
      display: 'flex', gap: 14, alignItems: 'center',
      animation: `fadeUp 0.3s ease ${index * 0.06}s both`,
    }}>
      <CircleProgress percentage={course.percentage} />

      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4, color: 'var(--text-primary)' }}>
          {course.course_name}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <span style={{
            padding: '2px 7px', borderRadius: 5,
            background: s.bg, color: s.color,
            fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.4,
          }}>{s.label}</span>
        </div>

        {/* Progress bar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{
            flex: 1, height: 4, borderRadius: 2,
            background: 'var(--bg-elevated)', overflow: 'hidden',
          }}>
            <div style={{
              height: '100%',
              width: `${course.percentage}%`,
              background: course.status === 'ok' ? 'var(--green)'
                : course.status === 'warning' ? 'var(--yellow)' : 'var(--red)',
              borderRadius: 2,
              transition: 'width 0.8s ease',
            }} />
          </div>
          <span style={{
            fontSize: 11, color: 'var(--text-muted)',
            fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap',
          }}>
            {course.attended}/{course.total}
          </span>
        </div>

        {course.status !== 'ok' && (
          <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', marginTop: 5 }}>
            ⚠️ Пропущено {course.missed} из {course.total} занятий
          </div>
        )}
      </div>
    </div>
  )
}

export default function AttendancePage() {
  const { student } = useAuth()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!student?.student_id) return
    setData(null)
    setLoading(true)
    async function load() {
      try {
        const res = await api.getAttendance(student.student_id)
        setData(res)
      } catch (e) {
        console.error(e)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [student?.student_id])

  const overall = data?.overall_percentage || 0
  const overallColor = overall >= 75 ? 'var(--green)' : overall >= 50 ? 'var(--yellow)' : 'var(--red)'

  return (
    <div className="page">
      <div className="page-header">
        <div className="page-title">Посещаемость</div>
        <div className="page-subtitle">Текущий семестр</div>
      </div>

      <div className="scroll-area" style={{ flex: 1 }}>
        {/* Overall card */}
        {data && (
          <div style={{
            margin: '12px 16px 8px',
            padding: '20px',
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            display: 'flex', alignItems: 'center', gap: 20,
            animation: 'fadeUp 0.3s ease',
          }}>
            <CircleProgress percentage={overall} size={80} strokeWidth={6} />
            <div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 4 }}>
                Общая посещаемость
              </div>
              <div style={{ fontSize: 28, fontWeight: 700, color: overallColor, fontFamily: 'var(--font-mono)', lineHeight: 1 }}>
                {overall.toFixed(1)}%
              </div>
              {data.has_issues && (
                <div style={{ fontSize: 12.5, color: 'var(--yellow)', marginTop: 6 }}>
                  ⚠️ Низкая посещаемость в {data.low_attendance_courses.length} курс(ах)
                </div>
              )}
              {!data.has_issues && (
                <div style={{ fontSize: 12.5, color: 'var(--green)', marginTop: 6 }}>
                  ✅ Всё в порядке
                </div>
              )}
            </div>
          </div>
        )}

        {/* Warning banner */}
        {data?.has_issues && (
          <div style={{
            margin: '0 16px 8px',
            padding: '12px 14px',
            background: 'var(--yellow-dim)',
            border: '1px solid rgba(251,191,36,0.3)',
            borderRadius: 'var(--radius-sm)',
            fontSize: 13, color: 'var(--yellow)',
            animation: 'fadeUp 0.35s ease',
          }}>
            ⚠️ Минимальная посещаемость в SDU — <strong>75%</strong>. Риск не допуска к экзамену.
          </div>
        )}

        {/* Course list */}
        <div style={{ padding: '8px 16px 16px' }}>
          {loading ? (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>Загрузка...</div>
          ) : (
            (data?.courses || [])
              .sort((a, b) => a.percentage - b.percentage)
              .map((c, i) => <AttendanceCard key={c.course_code} course={c} index={i} />)
          )}
        </div>
      </div>
    </div>
  )
}
