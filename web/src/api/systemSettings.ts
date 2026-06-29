import http from './http'

export interface SystemSettings {
  serverHost: string
  serverPort: number
  mode: string
  failOpen: boolean
  maxBodySize: number
  enableSemantic: boolean
  enableXdp: boolean
  databaseDriver: string
  rulesDirectory: string
  loggingLevel: string
}

const fallback: SystemSettings = {
  serverHost: '127.0.0.1',
  serverPort: 9090,
  mode: 'debug',
  failOpen: true,
  maxBodySize: 10485760,
  enableSemantic: true,
  enableXdp: false,
  databaseDriver: 'sqlite',
  rulesDirectory: 'rules',
  loggingLevel: 'info',
}

export async function fetchSystemSettings(): Promise<SystemSettings> {
  try {
    const { data } = await http.get<SystemSettings>('/settings')
    return data
  } catch {
    return fallback
  }
}
