import React, { useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom'
import { initSecurity } from './utils/security'
import './App.css'
import './enable-copy.css'

// Context
import { AuthProvider } from './context/AuthContext'

// Components
import Navbar from './components/Navbar'
import Footer from './components/Footer'
import ProtectedRoute from './components/ProtectedRoute'
import ScrollToTop from './components/ScrollToTop'
import BackToTopButton from './components/BackToTopButton'

// Pages
import Home from './pages/Home'
import Challenges from './pages/Challenges'

import About from './pages/About'
import Login from './pages/Login'
import Register from './pages/Register'
import Profile from './pages/Profile'
import Leaderboard from './pages/Leaderboard'
import CreateChallenge from './pages/CreateChallenge'
import EditChallenge from './pages/EditChallenge'
import AdminDashboard from './pages/AdminDashboard'
import AdminCreateUser from './pages/AdminCreateUser'
import AdminCreateTeam from './pages/AdminCreateTeam'
import PrivacyPolicy from './pages/PrivacyPolicy'
import TermsOfService from './pages/TermsOfService'
import Documentation from './pages/Documentation'
import AdminUserProfile from './pages/AdminUserProfile'
import ContactUs from './pages/ContactUs'
import AdminContactMessages from './pages/AdminContactMessages'
import AdminLoginLogs from './pages/AdminLoginLogs'
import PlatformControl from './pages/PlatformControl'
import PlatformReset from './pages/PlatformReset'
import UserBlocked from './pages/UserBlocked'
import ChallengeDetails from './pages/ChallengeDetails'
import Notice from './pages/Notice'
import Analytics from './pages/Analytics'
import AdminSubmissions from './pages/AdminSubmissions'
import UserProfile from './pages/UserProfile'
import AdminLiveMonitor from './pages/AdminLiveMonitor'

function App() {
  useEffect(() => {
    initSecurity();

    // Force enable right-click and text selection
    document.addEventListener('DOMContentLoaded', () => {
      // Remove any existing event listeners that prevent right-click
      document.oncontextmenu = null;
      document.onselectstart = null;
      document.ondragstart = null;

      // Enable text selection on all elements
      const style = document.createElement('style');
      style.textContent = `
        * {
          user-select: text !important;
          -webkit-user-select: text !important;
          -moz-user-select: text !important;
          -ms-user-select: text !important;
        }
      `;
      document.head.appendChild(style);
    });

    // Also run immediately
    document.oncontextmenu = null;
    document.onselectstart = null;
    document.ondragstart = null;
  }, []);

  return (
    <AuthProvider>
      <Router>
        <ScrollToTop />
        <div className="app-container">
          <Navbar />
          <main className="main-content">
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/challenges" element={
                <ProtectedRoute>
                  <Challenges />
                </ProtectedRoute>
              } />
              <Route path="/challenges/:id" element={
                <ProtectedRoute>
                  <ChallengeDetails />
                </ProtectedRoute>
              } />

              <Route path="/about" element={<About />} />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/contact" element={<ContactUs />} />
              <Route path="/notices" element={<Notice />} />
              <Route path="/profile" element={
                <ProtectedRoute>
                  <Profile />
                </ProtectedRoute>
              } />
              <Route path="/leaderboard" element={
                <ProtectedRoute>
                  <Leaderboard />
                </ProtectedRoute>
              } />
              <Route path="/user/:userId" element={
                <ProtectedRoute>
                  <UserProfile />
                </ProtectedRoute>
              } />
              <Route path="/create-challenge" element={
                <ProtectedRoute adminOnly={true}>
                  <CreateChallenge />
                </ProtectedRoute>
              } />
              <Route path="/edit-challenge/:id" element={
                <ProtectedRoute adminOnly={true}>
                  <EditChallenge />
                </ProtectedRoute>
              } />
              <Route path="/admin" element={
                <ProtectedRoute adminOnly={true}>
                  <AdminDashboard />
                </ProtectedRoute>
              } />
              <Route path="/admin/create-user" element={
                <ProtectedRoute adminOnly={true}>
                  <AdminCreateUser />
                </ProtectedRoute>
              } />
              <Route path="/admin/create-team" element={
                <ProtectedRoute adminOnly={true}>
                  <AdminCreateTeam />
                </ProtectedRoute>
              } />
              <Route path="/admin/messages" element={
                <ProtectedRoute adminOnly={true}>
                  <AdminContactMessages />
                </ProtectedRoute>
              } />
              <Route path="/admin/login-logs" element={
                <ProtectedRoute adminOnly={true}>
                  <AdminLoginLogs />
                </ProtectedRoute>
              } />
              <Route path="/admin/users/:id" element={
                <ProtectedRoute adminOnly={true}>
                  <AdminUserProfile />
                </ProtectedRoute>
              } />
              <Route path="/admin/platform-control" element={
                <ProtectedRoute adminOnly={true}>
                  <PlatformControl />
                </ProtectedRoute>
              } />
              <Route path="/admin/platform-reset" element={
                <ProtectedRoute adminOnly={true}>
                  <PlatformReset />
                </ProtectedRoute>
              } />
              <Route path="/admin/analytics" element={
                <ProtectedRoute adminOnly={true}>
                  <Analytics />
                </ProtectedRoute>
              } />
              <Route path="/admin/submissions" element={
                <ProtectedRoute adminOnly={true}>
                  <AdminSubmissions />
                </ProtectedRoute>
              } />
              <Route path="/admin/live-monitor" element={
                <ProtectedRoute adminOnly={true}>
                  <AdminLiveMonitor />
                </ProtectedRoute>
              } />
              <Route path="/blocked" element={<UserBlocked />} />
              <Route path="/privacy-policy" element={<PrivacyPolicy />} />
              <Route path="/terms-of-service" element={<TermsOfService />} />
              <Route path="/documentation" element={<Documentation />} />
            </Routes>
          </main>
          <Footer />
          <BackToTopButton />
        </div>
      </Router>
    </AuthProvider>
  )
}

export default App
