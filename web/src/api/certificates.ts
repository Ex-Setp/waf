import http from './http'

export interface CertificateItem {
  id: string
  name: string
  domains: string[]
  certPem?: string
  issuer?: string
  subject?: string
  notBefore?: number
  notAfter?: number
  hasPrivateKey: boolean
  createdAt: string
  updatedAt: string
}

export interface CertificateListResponse {
  certificates: CertificateItem[]
  total: number
}

export interface CertificatePayload {
  name: string
  domains: string[]
  certPem: string
  keyPem: string
}

export async function fetchCertificates(): Promise<CertificateListResponse> {
  const { data } = await http.get<CertificateListResponse>('/certificates')
  return data
}

export async function createCertificate(payload: CertificatePayload): Promise<CertificateItem> {
  const { data } = await http.post<CertificateItem>('/certificates', payload)
  return data
}

export async function deleteCertificate(id: string): Promise<void> {
  await http.delete(`/certificates/${id}`)
}
