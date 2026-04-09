import { createContext, useContext, useState, useEffect } from 'react'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [student, setStudent] = useState(() => {
    try {
      const saved = sessionStorage.getItem('sdu_student')
      return saved ? JSON.parse(saved) : null
    } catch { return null }
  })

  function login(data) {
    // Save all fields returned from backend
    const studentData = {
      student_id: data.student_id,
      name: data.name,
      firstname: data.firstname || '',
      lastname: data.lastname || '',
      fullname_native: data.fullname_native || '',
      username: data.username || data.student_id,
      email: data.email || '',
      avatar: data.avatar || '',
      portal_photo_url: data.portal_photo_url || '',
      program: data.program || '',
      advisor: data.advisor || '',
      birth_date: data.birth_date || '',
      status: data.status || '',
      grant_type: data.grant_type || '',
      token: data.token,
    }
    setStudent(studentData)
    try { sessionStorage.setItem('sdu_student', JSON.stringify(studentData)) } catch {}
  }

  function logout() {
    setStudent(null)
    try { sessionStorage.removeItem('sdu_student') } catch {}
  }

  function updateStudent(profileData) {
    const updated = { ...student, ...profileData }
    setStudent(updated)
    try { sessionStorage.setItem('sdu_student', JSON.stringify(updated)) } catch {}
  }

  return (
    <AuthContext.Provider value={{ student, login, logout, updateStudent }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
