import { useState, FormEvent } from 'react'
import { User, Role } from '../types'

interface UserFormProps {
  user: User | null
  roles: Role[]
  onSave: (data: Partial<User>) => void
  onCancel: () => void
}

export function UserForm({ user, roles, onSave, onCancel }: UserFormProps) {
  const [username, setUsername] = useState(user?.username || '')
  const [email, setEmail] = useState(user?.email || '')
  const [password, setPassword] = useState('')
  const [roleId, setRoleId] = useState(user?.roleId || (roles[0]?.id ?? ''))
  const [active, setActive] = useState(user?.active !== false)

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    const data: Partial<User> & { password?: string } = {
      username,
      email: email || undefined,
      roleId,
      active,
    }
    if (password) {
      data.password = password
    }
    onSave(data)
  }

  const isEditing = user !== null

  return (
    <div className="modal-overlay" onClick={onCancel}>
      <form
        className="modal-content"
        onClick={(e) => e.stopPropagation()}
        onSubmit={handleSubmit}
      >
        <div className="modal-title">{isEditing ? 'Edit User' : 'New User'}</div>

        <div className="form-group">
          <label className="form-label">Username</label>
          <input
            className="form-input"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={isEditing}
            required
            autoFocus={!isEditing}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Email</label>
          <input
            className="form-input"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="user@example.com"
          />
        </div>

        <div className="form-group">
          <label className="form-label">
            {isEditing ? 'Password (leave blank to keep current)' : 'Password'}
          </label>
          <input
            className="form-input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required={!isEditing}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Role</label>
          <select
            className="form-select"
            value={roleId}
            onChange={(e) => setRoleId(e.target.value)}
          >
            {roles.map((role) => (
              <option key={role.id} value={role.id}>{role.id}</option>
            ))}
          </select>
        </div>

        <div className="form-group">
          <label className="form-checkbox-row">
            <input
              type="checkbox"
              checked={active}
              onChange={(e) => setActive(e.target.checked)}
            />
            <span>Active</span>
          </label>
        </div>

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
