import { useState, useEffect, useCallback } from 'react'
import { api, BASE } from '../api'
import { Role } from '../types'
import { RoleForm } from './RoleForm'

interface RolesPageProps {
  showToast: (message: string, type: 'success' | 'error') => void
}

export function RolesPage({ showToast }: RolesPageProps) {
  const [roles, setRoles] = useState<Role[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editingRole, setEditingRole] = useState<Role | null>(null)

  const loadRoles = useCallback(async () => {
    try {
      const data = await api<Role[]>(`${BASE}/roles`)
      setRoles(data)
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to load roles', 'error')
    } finally {
      setLoading(false)
    }
  }, [showToast])

  useEffect(() => { loadRoles() }, [loadRoles])

  const handleDelete = async (id: string) => {
    if (id === 'super_user') {
      showToast('Cannot delete super_user role', 'error')
      return
    }
    if (!confirm(`Delete role "${id}"?`)) return
    try {
      await api(`${BASE}/roles/${encodeURIComponent(id)}`, { method: 'DELETE' })
      showToast(`Role "${id}" deleted`, 'success')
      loadRoles()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Delete failed', 'error')
    }
  }

  const handleSave = async (data: { id: string; name: string; permissions: unknown }) => {
    try {
      if (editingRole) {
        await api(`${BASE}/roles/${encodeURIComponent(editingRole.id)}`, {
          method: 'PUT',
          body: JSON.stringify(data),
        })
        showToast(`Role "${editingRole.id}" updated`, 'success')
      } else {
        await api(`${BASE}/roles`, {
          method: 'POST',
          body: JSON.stringify(data),
        })
        showToast(`Role "${data.id}" created`, 'success')
      }
      setShowForm(false)
      setEditingRole(null)
      loadRoles()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    }
  }

  const summarizePermissions = (perms: string | Record<string, unknown>): string => {
    try {
      const perm = typeof perms === 'string' ? JSON.parse(perms) : perms
      if (perm.super_user) return 'Super User (full access)'
      const dbCount = Object.keys(perm.databases || {}).length
      if (dbCount === 0) return 'No permissions'
      const tableCount = Object.values(perm.databases || {}).reduce(
        (sum: number, db: unknown) => sum + Object.keys((db as { tables: Record<string, unknown> }).tables || {}).length, 0
      )
      return `${dbCount} database(s), ${tableCount} table(s)`
    } catch {
      return 'Invalid permissions'
    }
  }

  if (loading) return <div className="page-body empty-state">Loading...</div>

  return (
    <>
      <div className="page-header">
        <div className="page-title">Roles</div>
        <button className="btn btn-primary" onClick={() => { setEditingRole(null); setShowForm(true) }}>
          New Role
        </button>
      </div>
      <div className="page-body">
        {roles.length === 0 ? (
          <div className="empty-state">No roles found</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Permissions</th>
                <th className="col-actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              {roles.map((role) => (
                <tr key={role.id}>
                  <td>{role.id}</td>
                  <td>{role.name}</td>
                  <td>{summarizePermissions(role.permissions)}</td>
                  <td className="col-actions">
                    <div className="btn-group">
                      <button
                        className="btn btn-sm"
                        onClick={() => { setEditingRole(role); setShowForm(true) }}
                      >
                        Edit
                      </button>
                      <button
                        className="btn btn-sm btn-danger"
                        onClick={() => handleDelete(role.id)}
                        disabled={role.id === 'super_user'}
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
        <RoleForm
          role={editingRole}
          onSave={handleSave}
          onCancel={() => { setShowForm(false); setEditingRole(null) }}
        />
      )}
    </>
  )
}
