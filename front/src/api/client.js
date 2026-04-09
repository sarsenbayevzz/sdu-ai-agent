const BASE_URL = import.meta.env.VITE_API_URL || '/api'

function getToken() {
  try {
    const saved = sessionStorage.getItem('sdu_student')
    if (saved) return JSON.parse(saved).token || ''
  } catch {}
  return ''
}

async function request(path, options = {}) {
  const token = getToken()
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...options.headers,
    },
    ...options,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  // Auth
  login: (studentId, password, portalPassword = '') =>
    request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        student_id: studentId,
        password,
        portal_password: portalPassword,
      }),
    }),

  verify2fa: (studentId, code) =>
    request(`/auth/portal-2fa?student_id=${studentId}&code=${code}`, { method: 'POST' }),

  // Chat
  sendMessage: (message, studentId) =>
    request('/chat/', {
      method: 'POST',
      body: JSON.stringify({ message, student_id: studentId }),
    }),

  // Assignments
  getAssignments: (studentId, days = 30) =>
    request(`/assignments/?student_id=${studentId}&days=${days}`),

  // Schedule
  getScheduleToday: (studentId) =>
    request(`/schedule/today?student_id=${studentId}`),

  getNextClass: (studentId) =>
    request(`/schedule/next?student_id=${studentId}`),

  getWeeklySchedule: (studentId) =>
    request(`/schedule/week?student_id=${studentId}`),

  // Attendance
  getAttendance: (studentId) =>
    request(`/attendance/?student_id=${studentId}`),
}
