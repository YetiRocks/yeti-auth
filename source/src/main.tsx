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

const VALID_PAGES: Page[] = ['dashboard', 'users', 'roles', 'oauth']

function getPageFromHash(): Page {
  const hash = window.location.hash.replace('#', '')
  return VALID_PAGES.includes(hash as Page) ? (hash as Page) : 'dashboard'
}

function App() {
  const [page, setPage] = useState<Page>(getPageFromHash)
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null)

  const showToast = useCallback((message: string, type: 'success' | 'error' = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3000)
  }, [])

  const navigate = useCallback((p: Page) => {
    window.location.hash = p
    setPage(p)
  }, [])

  useEffect(() => {
    const onHashChange = () => setPage(getPageFromHash())
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
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
