import { ReactNode } from 'react'

type Page = 'dashboard' | 'users' | 'roles' | 'oauth'

interface LayoutProps {
  currentPage: Page
  onNavigate: (page: Page) => void
  children: ReactNode
}

const navItems: { page: Page; label: string }[] = [
  { page: 'dashboard', label: 'Dashboard' },
  { page: 'users', label: 'Users' },
  { page: 'roles', label: 'Roles' },
  { page: 'oauth', label: 'OAuth Providers' },
]

export function Layout({ currentPage, onNavigate, children }: LayoutProps) {
  return (
    <div className="app-shell">
      <header className="header">
        <div className="header-left">
          <img src="logo_white.svg" alt="Yeti" className="logo" />
        </div>
        <div className="header-title">Auth Manager</div>
      </header>

      <div className="body-layout">
        <nav className="sidebar">
          {navItems.map(({ page, label }) => (
            <div
              key={page}
              className={`nav-item ${currentPage === page ? 'active' : ''}`}
              onClick={() => onNavigate(page)}
            >
              {label}
            </div>
          ))}
        </nav>
        <div className="main-content">
          {children}
        </div>
      </div>
    </div>
  )
}
