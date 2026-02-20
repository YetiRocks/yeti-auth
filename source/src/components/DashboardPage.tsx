import { useState, useEffect } from 'react'
import { api, BASE } from '../api'
import { User, Role, OAuthProvider } from '../types'

type Page = 'dashboard' | 'users' | 'roles' | 'oauth'

interface DashboardPageProps {
  onNavigate: (page: Page) => void
  showToast: (message: string, type: 'success' | 'error') => void
}

export function DashboardPage({ onNavigate, showToast }: DashboardPageProps) {
  const [userCount, setUserCount] = useState<number | null>(null)
  const [roleCount, setRoleCount] = useState<number | null>(null)
  const [providerCount, setProviderCount] = useState<number | null>(null)

  useEffect(() => {
    api<User[]>(`${BASE}/users`)
      .then((users) => setUserCount(users.length))
      .catch(() => showToast('Failed to load users', 'error'))

    api<Role[]>(`${BASE}/roles`)
      .then((roles) => setRoleCount(roles.length))
      .catch(() => showToast('Failed to load roles', 'error'))

    api<{ providers: OAuthProvider[] }>(`${BASE}/oauth_providers`)
      .then((data) => setProviderCount(data.providers.length))
      .catch(() => setProviderCount(0))
  }, [showToast])

  return (
    <>
      <div className="page-header">
        <div className="page-title">Dashboard</div>
      </div>
      <div className="page-body">
        <div className="stat-cards">
          <div className="stat-card" onClick={() => onNavigate('users')}>
            <div className="stat-card-value">{userCount ?? '...'}</div>
            <div className="stat-card-label">Users</div>
          </div>
          <div className="stat-card" onClick={() => onNavigate('roles')}>
            <div className="stat-card-value">{roleCount ?? '...'}</div>
            <div className="stat-card-label">Roles</div>
          </div>
          <div className="stat-card" onClick={() => onNavigate('oauth')}>
            <div className="stat-card-value">{providerCount ?? '...'}</div>
            <div className="stat-card-label">OAuth Providers</div>
          </div>
        </div>
      </div>
    </>
  )
}
