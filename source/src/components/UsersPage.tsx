import { useState, useEffect, useCallback } from 'react'
import { api, BASE } from '../api'
import { User, Role } from '../types'
import { UserForm } from './UserForm'

interface UsersPageProps {
  showToast: (message: string, type: 'success' | 'error') => void
}

export function UsersPage({ showToast }: UsersPageProps) {
  const [users, setUsers] = useState<User[]>([])
  const [roles, setRoles] = useState<Role[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editingUser, setEditingUser] = useState<User | null>(null)

  const loadData = useCallback(async () => {
    try {
      const [usersData, rolesData] = await Promise.all([
        api<User[]>(`${BASE}/users`),
        api<Role[]>(`${BASE}/roles`),
      ])
      setUsers(usersData)
      setRoles(rolesData)
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to load data', 'error')
    } finally {
      setLoading(false)
    }
  }, [showToast])

  useEffect(() => { loadData() }, [loadData])

  const handleDelete = async (username: string) => {
    if (!confirm(`Delete user "${username}"?`)) return
    try {
      await api(`${BASE}/users/${encodeURIComponent(username)}`, { method: 'DELETE' })
      showToast(`User "${username}" deleted`, 'success')
      loadData()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Delete failed', 'error')
    }
  }

  const handleSave = async (data: Partial<User>) => {
    try {
      if (editingUser) {
        await api(`${BASE}/users/${encodeURIComponent(editingUser.username)}`, {
          method: 'PUT',
          body: JSON.stringify(data),
        })
        showToast(`User "${editingUser.username}" updated`, 'success')
      } else {
        await api(`${BASE}/users`, {
          method: 'POST',
          body: JSON.stringify(data),
        })
        showToast(`User "${data.username}" created`, 'success')
      }
      setShowForm(false)
      setEditingUser(null)
      loadData()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    }
  }

  if (loading) return <div className="page-body empty-state">Loading...</div>

  return (
    <>
      <div className="page-header">
        <div className="page-title">Users</div>
        <button className="btn btn-primary" onClick={() => { setEditingUser(null); setShowForm(true) }}>
          New User
        </button>
      </div>
      <div className="page-body">
        {users.length === 0 ? (
          <div className="empty-state">No users found</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th className="col-actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.username}>
                  <td>{user.username}</td>
                  <td>{user.email || '-'}</td>
                  <td>{user.roleId}</td>
                  <td>
                    <span className={`badge ${user.active !== false ? 'badge-success' : 'badge-error'}`}>
                      {user.active !== false ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="col-actions">
                    <div className="btn-group">
                      <button
                        className="btn btn-sm"
                        onClick={() => { setEditingUser(user); setShowForm(true) }}
                      >
                        Edit
                      </button>
                      <button
                        className="btn btn-sm btn-danger"
                        onClick={() => handleDelete(user.username)}
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showForm && (
        <UserForm
          user={editingUser}
          roles={roles}
          onSave={handleSave}
          onCancel={() => { setShowForm(false); setEditingUser(null) }}
        />
      )}
    </>
  )
}
