import { useState, FormEvent } from 'react'
import { OAuthProvider } from '../types'

interface FieldDef {
  key: string
  label: string
  placeholder: string
  type?: 'text' | 'password' | 'textarea'
  required?: boolean
  help?: string
}

interface ProviderTemplate {
  label: string
  type: string
  description: string
  authorize_url: string
  token_url: string
  user_info_url: string
  user_emails_url?: string
  default_scopes: string[]
  fields: FieldDef[]
}

const PROVIDER_TEMPLATES: ProviderTemplate[] = [
  {
    label: 'GitHub',
    type: 'github',
    description: 'GitHub OAuth App or GitHub App',
    authorize_url: 'https://github.com/login/oauth/authorize',
    token_url: 'https://github.com/login/oauth/access_token',
    user_info_url: 'https://api.github.com/user',
    user_emails_url: 'https://api.github.com/user/emails',
    default_scopes: ['read:user', 'user:email'],
    fields: [
      { key: 'client_id', label: 'Client ID', placeholder: 'Ov23li...', type: 'text', required: true },
      { key: 'client_secret', label: 'Client Secret', placeholder: 'GitHub OAuth app secret', type: 'password', required: true },
    ],
  },
  {
    label: 'Google',
    type: 'google',
    description: 'Google Cloud OAuth 2.0 credentials',
    authorize_url: 'https://accounts.google.com/o/oauth2/v2/auth',
    token_url: 'https://oauth2.googleapis.com/token',
    user_info_url: 'https://www.googleapis.com/oauth2/v3/userinfo',
    default_scopes: ['openid', 'email', 'profile'],
    fields: [
      { key: 'client_id', label: 'Client ID', placeholder: '123456789.apps.googleusercontent.com', type: 'text', required: true },
      { key: 'client_secret', label: 'Client Secret', placeholder: 'GOCSPX-...', type: 'password', required: true },
    ],
  },
  {
    label: 'Microsoft',
    type: 'microsoft',
    description: 'Azure AD / Microsoft Entra ID',
    authorize_url: 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize',
    token_url: 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
    user_info_url: 'https://graph.microsoft.com/v1.0/me',
    default_scopes: ['openid', 'email', 'profile'],
    fields: [
      { key: 'tenant_id', label: 'Tenant ID', placeholder: 'common', type: 'text', required: true, help: 'Use "common" for multi-tenant, or your Azure AD tenant ID' },
      { key: 'client_id', label: 'Application (Client) ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', type: 'text', required: true },
      { key: 'client_secret', label: 'Client Secret', placeholder: 'Azure app client secret value', type: 'password', required: true },
    ],
  },
  {
    label: 'Auth0',
    type: 'auth0',
    description: 'Auth0 by Okta',
    authorize_url: 'https://{domain}/authorize',
    token_url: 'https://{domain}/oauth/token',
    user_info_url: 'https://{domain}/userinfo',
    default_scopes: ['openid', 'email', 'profile'],
    fields: [
      { key: 'domain', label: 'Domain', placeholder: 'your-tenant.auth0.com', type: 'text', required: true },
      { key: 'client_id', label: 'Client ID', placeholder: 'Auth0 application client ID', type: 'text', required: true },
      { key: 'client_secret', label: 'Client Secret', placeholder: 'Auth0 application client secret', type: 'password', required: true },
    ],
  },
  {
    label: 'Apple',
    type: 'apple',
    description: 'Sign in with Apple',
    authorize_url: 'https://appleid.apple.com/auth/authorize',
    token_url: 'https://appleid.apple.com/auth/token',
    user_info_url: 'https://appleid.apple.com/auth/userinfo',
    default_scopes: ['name', 'email'],
    fields: [
      { key: 'client_id', label: 'Service ID', placeholder: 'com.example.app', type: 'text', required: true, help: 'The Services ID from your Apple Developer account' },
      { key: 'team_id', label: 'Team ID', placeholder: 'ABCDE12345', type: 'text', required: true },
      { key: 'key_id', label: 'Key ID', placeholder: 'ABC123DEFG', type: 'text', required: true, help: 'From the Sign in with Apple private key' },
      { key: 'private_key', label: 'Private Key', placeholder: '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----', type: 'textarea', required: true, help: 'The .p8 key file contents. Used to generate the client secret JWT.' },
    ],
  },
  {
    label: 'Okta',
    type: 'okta',
    description: 'Okta Workforce / Customer Identity',
    authorize_url: 'https://{domain}/oauth2/default/v1/authorize',
    token_url: 'https://{domain}/oauth2/default/v1/token',
    user_info_url: 'https://{domain}/oauth2/default/v1/userinfo',
    default_scopes: ['openid', 'email', 'profile'],
    fields: [
      { key: 'domain', label: 'Okta Domain', placeholder: 'your-org.okta.com', type: 'text', required: true },
      { key: 'client_id', label: 'Client ID', placeholder: 'Okta application client ID', type: 'text', required: true },
      { key: 'client_secret', label: 'Client Secret', placeholder: 'Okta application client secret', type: 'password', required: true },
    ],
  },
]

interface AddProviderModalProps {
  provider: OAuthProvider | null
  onSave: (data: Record<string, unknown>) => void
  onCancel: () => void
}

export function AddProviderModal({ provider, onSave, onCancel }: AddProviderModalProps) {
  const isEditing = provider !== null
  const [selectedType, setSelectedType] = useState(provider?.type || '')
  const [name, setName] = useState(provider?.name || '')
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({})
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [scopes, setScopes] = useState(provider?.scopes.join(', ') || '')
  const [authorizeUrl, setAuthorizeUrl] = useState(provider?.authorize_url || '')
  const [tokenUrl, setTokenUrl] = useState('')
  const [userInfoUrl, setUserInfoUrl] = useState('')
  const [userEmailsUrl, setUserEmailsUrl] = useState('')
  const [error, setError] = useState('')

  const template = PROVIDER_TEMPLATES.find((t) => t.type === selectedType)

  const handleSelectProvider = (type: string) => {
    const tpl = PROVIDER_TEMPLATES.find((t) => t.type === type)
    setSelectedType(type)
    setError('')
    if (tpl) {
      if (!isEditing) setName(tpl.type)
      setScopes(tpl.default_scopes.join(', '))
      setAuthorizeUrl(tpl.authorize_url)
      setTokenUrl(tpl.token_url)
      setUserInfoUrl(tpl.user_info_url)
      setUserEmailsUrl(tpl.user_emails_url || '')
      setFieldValues({})
      setShowAdvanced(false)
    }
  }

  const setField = (key: string, value: string) => {
    setFieldValues((prev) => ({ ...prev, [key]: value }))
  }

  const resolveUrl = (url: string): string => {
    let resolved = url
    for (const [key, val] of Object.entries(fieldValues)) {
      resolved = resolved.split(`{${key}}`).join(val)
    }
    return resolved
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    setError('')

    if (!selectedType || !template) {
      setError('Select a provider')
      return
    }
    if (!name.trim()) {
      setError('Name is required')
      return
    }

    for (const field of template.fields) {
      if (field.required && !isEditing && !fieldValues[field.key]?.trim()) {
        setError(`${field.label} is required`)
        return
      }
      if (field.required && isEditing && field.key === 'client_id' && !fieldValues[field.key]?.trim()) {
        setError(`${field.label} is required`)
        return
      }
    }

    const data: Record<string, unknown> = {
      name: name.trim(),
      provider_type: selectedType,
      authorize_url: resolveUrl(authorizeUrl),
      token_url: resolveUrl(tokenUrl),
      user_info_url: resolveUrl(userInfoUrl),
      scopes: scopes.split(',').map((s) => s.trim()).filter(Boolean),
    }

    if (userEmailsUrl.trim()) {
      data.user_emails_url = resolveUrl(userEmailsUrl.trim())
    }

    for (const field of template.fields) {
      const val = fieldValues[field.key]?.trim()
      if (val) {
        data[field.key] = val
      }
    }

    onSave(data)
  }

  return (
    <div className="modal-overlay" onClick={onCancel}>
      <form
        className="modal-content modal-wide"
        onClick={(e) => e.stopPropagation()}
        onSubmit={handleSubmit}
      >
        <div className="modal-title">{isEditing ? 'Edit OAuth Provider' : 'Add OAuth Provider'}</div>

        <div className="form-group">
          <label className="form-label">Provider</label>
          <select
            className="form-select"
            value={selectedType}
            onChange={(e) => handleSelectProvider(e.target.value)}
            disabled={isEditing}
          >
            <option value="">Select a provider...</option>
            {PROVIDER_TEMPLATES.map((tpl) => (
              <option key={tpl.type} value={tpl.type}>{tpl.label}</option>
            ))}
          </select>
          {template && <div className="form-hint">{template.description}</div>}
        </div>

        {selectedType && template && (
          <>
            <div className="form-group">
              <label className="form-label">Name</label>
              <input
                className="form-input"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. github, my-google-oauth"
                disabled={isEditing}
                required
              />
            </div>

            {template.fields.map((field) => (
              <div className="form-group" key={field.key}>
                <label className="form-label">
                  {field.label}
                  {isEditing && field.type === 'password' && ' (leave blank to keep)'}
                </label>
                {field.type === 'textarea' ? (
                  <textarea
                    className="form-textarea form-textarea-sm"
                    value={fieldValues[field.key] || ''}
                    onChange={(e) => setField(field.key, e.target.value)}
                    placeholder={field.placeholder}
                    required={field.required && !isEditing}
                  />
                ) : (
                  <input
                    className="form-input"
                    type={field.type || 'text'}
                    value={fieldValues[field.key] || ''}
                    onChange={(e) => setField(field.key, e.target.value)}
                    placeholder={field.placeholder}
                    required={field.required && !isEditing}
                  />
                )}
                {field.help && <div className="form-hint">{field.help}</div>}
              </div>
            ))}

            <button
              type="button"
              className="btn btn-sm"
              onClick={() => setShowAdvanced(!showAdvanced)}
            >
              {showAdvanced ? 'Hide' : 'Show'} Advanced
            </button>

            {showAdvanced && (
              <div className="advanced-fields">
                <div className="form-group">
                  <label className="form-label">Scopes</label>
                  <input
                    className="form-input"
                    type="text"
                    value={scopes}
                    onChange={(e) => setScopes(e.target.value)}
                    placeholder="Comma-separated scopes"
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Authorize URL</label>
                  <input
                    className="form-input"
                    type="text"
                    value={authorizeUrl}
                    onChange={(e) => setAuthorizeUrl(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Token URL</label>
                  <input
                    className="form-input"
                    type="text"
                    value={tokenUrl}
                    onChange={(e) => setTokenUrl(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">User Info URL</label>
                  <input
                    className="form-input"
                    type="text"
                    value={userInfoUrl}
                    onChange={(e) => setUserInfoUrl(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">User Emails URL</label>
                  <input
                    className="form-input"
                    type="text"
                    value={userEmailsUrl}
                    onChange={(e) => setUserEmailsUrl(e.target.value)}
                    placeholder="Optional — separate endpoint for user emails"
                  />
                </div>
              </div>
            )}
          </>
        )}

        {error && <div className="form-error">{error}</div>}

        <div className="modal-actions">
          <button type="button" className="btn" onClick={onCancel}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={!selectedType}>
            {isEditing ? 'Update' : 'Add Provider'}
          </button>
        </div>
      </form>
    </div>
  )
}
