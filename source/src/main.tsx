import { StrictMode, useState, useCallback, useEffect } from 'react'
import { createRoot } from 'react-dom/client'
import '@yeti/yeti.css'
import './index.css'
import { Layout } from './components/Layout'
import { DashboardPage } from './components/DashboardPage'
import { UsersPage } from './components/UsersPage'
import { RolesPage } from './components/RolesPage'
import { OAuthPage } from './components/OAuthPage'

type Page = 'dashboard' | 'users' | 'roles' | 'oauth'

const BASE = '/yeti-auth'
const VALID_PAGES: Page[] = ['dashboard', 'users', 'roles', 'oauth']

function getPageFromPath(): Page {
  const path = window.location.pathname.replace(BASE, '').replace(/^\//, '')
  return VALID_PAGES.includes(path as Page) ? (path as Page) : 'dashboard'
}

function App() {
  const [page, setPage] = useState<Page>(getPageFromPath)
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null)

  const showToast = useCallback((message: string, type: 'success' | 'error' = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3000)
  }, [])

  const navigate = useCallback((p: Page) => {
    window.history.pushState(null, '', `${BASE}/${p}`)
    setPage(p)
  }, [])

  useEffect(() => {
    const onPopState = () => setPage(getPageFromPath())
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  return (
    <Layout currentPage={page} onNavigate={navigate}>
      {page === 'dashboard' && <DashboardPage onNavigate={navigate} showToast={showToast} />}
      {page === 'users' && <UsersPage showToast={showToast} />}
      {page === 'roles' && <RolesPage showToast={showToast} />}
      {page === 'oauth' && <OAuthPage showToast={showToast} />}
      {toast && <div className={`toast ${toast.type}`}>{toast.message}</div>}
    </Layout>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
