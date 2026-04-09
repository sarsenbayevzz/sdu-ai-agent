import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './hooks/useAuth'
import BottomNav from './components/BottomNav'
import ChatPage from './pages/ChatPage'
import SchedulePage from './pages/SchedulePage'
import AssignmentsPage from './pages/AssignmentsPage'
import AttendancePage from './pages/AttendancePage'
import LoginPage from './pages/LoginPage'
import ProfilePage from './pages/ProfilePage'

function AppRoutes() {
  const { student } = useAuth()

  if (!student) {
    return (
      <Routes>
        <Route path="*" element={<LoginPage />} />
      </Routes>
    )
  }

  return (
    <>
      <Routes>
        <Route path="/" element={<Navigate to="/chat" replace />} />
        <Route path="/chat" element={<ChatPage />} />
        <Route path="/schedule" element={<SchedulePage />} />
        <Route path="/assignments" element={<AssignmentsPage />} />
        <Route path="/attendance" element={<AttendancePage />} />
        <Route path="/profile" element={<ProfilePage />} />
        <Route path="*" element={<Navigate to="/chat" replace />} />
      </Routes>
      <BottomNav />
    </>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  )
}
