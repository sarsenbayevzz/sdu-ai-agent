import { useState, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth'
import { api } from '../api/client'

const DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']
const DAY_RU = { Monday: 'Пн', Tuesday: 'Вт', Wednesday: 'Ср', Thursday: 'Чт', Friday: 'Пт' }
const DAY_FULL_RU = {
  Monday: 'Понедельник', Tuesday: 'Вторник', Wednesday: 'Среда',
  Thursday: 'Четверг', Friday: 'Пятница',
}
const TYPE_COLOR = {
  Lecture: { bg: 'var(--accent-dim)', color: 'var(--accent)', label: 'Лекция' },
  Lab: { bg: 'var(--green-dim)', color: 'var(--green)', label: 'Лаб' },
  Seminar: { bg: 'var(--yellow-dim)', color: 'var(--yellow)', label: 'Семинар' },
}

function ClassCard({ cls, index }) {
  const typeStyle = TYPE_COLOR[cls.class_type] || TYPE_COLOR.Lecture
  return (
    <div style={{
      display: 'flex', gap: 12,
      animation: `fadeUp 0.3s ease ${index * 0.05}s both`,
    }}>
      {/* Time column */}
      <div style={{
        width: 52, flexShrink: 0,
        display: 'flex', flexDirection: 'column', alignItems: 'center', paddingTop: 4,
      }}>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 12,
          color: 'var(--accent)', fontWeight: 500,
        }}>{cls.start_time}</span>
        <div style={{ width: 1, flex: 1, background: 'var(--border)', margin: '4px 0' }} />
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 11,
          color: 'var(--text-muted)',
        }}>{cls.end_time}</span>
      </div>

      {/* Card */}
      <div style={{
        flex: 1,
        background: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: '12px 14px',
        marginBottom: 10,
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
          <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', lineHeight: 1.3, flex: 1, marginRight: 8 }}>
            {cls.course_name}
          </span>
          <span style={{
            padding: '2px 8px', borderRadius: 6,
            background: typeStyle.bg, color: typeStyle.color,
            fontSize: 10, fontWeight: 700, letterSpacing: 0.4,
            textTransform: 'uppercase', flexShrink: 0,
          }}>
            {typeStyle.label}
          </span>
        </div>

        <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12.5, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <span>📍</span> {cls.room}
          </span>
          <span style={{ fontSize: 12.5, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <span>👤</span> {cls.teacher}
          </span>
        </div>
      </div>
    </div>
  )
}

export default function SchedulePage() {
  const { student } = useAuth()
  const [schedule, setSchedule] = useState(null)
  const [nextClass, setNextClass] = useState(null)
  const [activeDay, setActiveDay] = useState(new Date().toLocaleDateString('en-US', { weekday: 'long' }))
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!student?.student_id) return
    setSchedule(null)
    setLoading(true)
    async function load() {
      try {
        const [week, next] = await Promise.all([
          api.getWeeklySchedule(student.student_id),
          api.getNextClass(student.student_id),
        ])
        setSchedule(week.schedule)
        setNextClass(next)
      } catch (e) {
        console.error(e)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [student?.student_id])

  const todayEn = new Date().toLocaleDateString('en-US', { weekday: 'long' })
  const todayClasses = schedule?.[activeDay] || []

  return (
    <div className="page">
      {/* Header */}
      <div className="page-header">
        <div className="page-title">Расписание</div>
        <div className="page-subtitle">
          {new Date().toLocaleDateString('ru-RU', { weekday: 'long', day: 'numeric', month: 'long' })}
        </div>
      </div>

      <div className="scroll-area" style={{ flex: 1 }}>
        {/* Next class banner */}
        {nextClass?.course_name && (
          <div style={{
            margin: '12px 16px 0',
            padding: '12px 16px',
            background: 'linear-gradient(135deg, rgba(79,124,255,0.15), rgba(124,58,237,0.1))',
            border: '1px solid var(--border-active)',
            borderRadius: 'var(--radius)',
            animation: 'fadeUp 0.3s ease',
          }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 6 }}>
              {nextClass.is_today ? '⚡ Следующая пара' : nextClass.is_tomorrow ? '📅 Завтра' : `📅 ${DAY_FULL_RU[nextClass.day] || nextClass.day}`}
            </div>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 4 }}>{nextClass.course_name}</div>
            <div style={{ display: 'flex', gap: 12, fontSize: 12.5, color: 'var(--text-secondary)' }}>
              <span>🕐 {nextClass.start_time}–{nextClass.end_time}</span>
              <span>📍 {nextClass.room}</span>
              <span>👤 {nextClass.teacher}</span>
            </div>
          </div>
        )}

        {/* Day tabs */}
        <div style={{
          display: 'flex', gap: 6,
          padding: '12px 16px 8px',
          overflowX: 'auto', scrollbarWidth: 'none',
        }}>
          {DAYS.map(day => {
            const isActive = day === activeDay
            const isToday = day === todayEn
            const count = schedule?.[day]?.length || 0
            return (
              <button
                key={day}
                onClick={() => setActiveDay(day)}
                style={{
                  flexShrink: 0,
                  display: 'flex', flexDirection: 'column', alignItems: 'center',
                  padding: '8px 14px',
                  borderRadius: 'var(--radius-sm)',
                  background: isActive ? 'var(--accent)' : 'var(--bg-card)',
                  border: `1px solid ${isActive ? 'var(--accent)' : isToday ? 'var(--border-active)' : 'var(--border)'}`,
                  cursor: 'pointer',
                  transition: 'all 0.15s',
                  minWidth: 52,
                }}
              >
                <span style={{ fontSize: 11, fontWeight: 600, color: isActive ? 'white' : 'var(--text-secondary)', letterSpacing: 0.3 }}>
                  {DAY_RU[day]}
                </span>
                <span style={{
                  marginTop: 3, fontSize: 11,
                  fontFamily: 'var(--font-mono)',
                  color: isActive ? 'rgba(255,255,255,0.7)' : count > 0 ? 'var(--accent)' : 'var(--text-muted)',
                }}>
                  {count}
                </span>
              </button>
            )
          })}
        </div>

        {/* Classes list */}
        <div style={{ padding: '8px 16px 16px' }}>
          {loading ? (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40, fontSize: 14 }}>
              Загрузка...
            </div>
          ) : todayClasses.length === 0 ? (
            <div style={{
              textAlign: 'center', padding: '48px 20px',
              color: 'var(--text-secondary)', fontSize: 14,
            }}>
              <div style={{ fontSize: 36, marginBottom: 10 }}>🎉</div>
              Пар нет — выходной!
            </div>
          ) : (
            todayClasses.map((cls, i) => (
              <ClassCard key={i} cls={cls} index={i} />
            ))
          )}
        </div>
      </div>
    </div>
  )
}
