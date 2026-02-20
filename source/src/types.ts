export interface Permission {
  super_user: boolean
  databases: Record<string, DatabasePermission>
}

export interface DatabasePermission {
  tables: Record<string, TablePermission>
}

export interface TablePermission {
  read: boolean
  insert: boolean
  update: boolean
  delete: boolean
  attribute_permissions?: Record<string, AttributePermission>
}

export interface AttributePermission {
  read: boolean
  write: boolean
}

export interface Role {
  id: string
  name: string
  permissions: string | Record<string, unknown>
}

export interface User {
  username: string
  password?: string
  email?: string
  roleId: string
  active: boolean
}

export interface OAuthProvider {
  name: string
  type: string
  authorize_url: string
  scopes: string[]
}
