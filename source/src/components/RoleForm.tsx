import { useState, FormEvent } from 'react'
import { Role } from '../types'

interface RoleFormProps {
  role: Role | null
  onSave: (data: { id: string; name: string; permissions: unknown }) => void
  onCancel: () => void
}

export function RoleForm({ role, onSave, onCancel }: RoleFormProps) {
  const [id, setId] = useState(role?.id || '')
  const [name, setName] = useState(role?.name || '')
  const [permissions, setPermissions] = useState(
    role?.permissions
      ? toJsonString(role.permissions)
      : '{\n  "super_user": false,\n  "databases": {}\n}'
  )
  const [error, setError] = useState('')

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    setError('')

    // Validate JSON
    try {
      JSON.parse(permissions)
    } catch {
      setError('Invalid JSON in permissions')
      return
    }

    onSave({ id, name: name || id, permissions: JSON.parse(permissions) })
  }

  const isEditing = role !== null

  return (
    <div className="modal-overlay" onClick={onCancel}>
      <form
        className="modal-content"
        onClick={(e) => e.stopPropagation()}
        onSubmit={handleSubmit}
      >
        <div className="modal-title">{isEditing ? 'Edit Role' : 'New Role'}</div>

        <div className="form-group">
          <label className="form-label">Role ID</label>
          <input
            className="form-input"
            type="text"
            value={id}
            onChange={(e) => setId(e.target.value)}
            disabled={isEditing}
            required
            autoFocus={!isEditing}
            placeholder="e.g. editor, viewer"
          />
        </div>

        <div className="form-group">
          <label className="form-label">Display Name</label>
          <input
            className="form-input"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Editor, Viewer"
          />
        </div>

        <div className="form-group">
          <label className="form-label">Permissions (JSON)</label>
          <textarea
            className="form-textarea"
            value={permissions}
            onChange={(e) => setPermissions(e.target.value)}
            rows={12}
          />
        </div>

        {error && <div className="form-error">{error}</div>}

        <div className="modal-actions">
          <button type="button" className="btn" onClick={onCancel}>Cancel</button>
          <button type="submit" className="btn btn-primary">
            {isEditing ? 'Update' : 'Create'}
          </button>
        </div>
      </form>
    </div>
  )
}

function toJsonString(val: unknown): string {
  if (typeof val === 'string') {
    try {
      return JSON.stringify(JSON.parse(val), null, 2)
    } catch {
      return val
    }
  }
  return JSON.stringify(val, null, 2)
}
