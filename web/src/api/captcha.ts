import http from './http'

export type CaptchaMethod = 'image' | 'slider' | 'button'

export interface CaptchaTrigger {
  id: string
  name: string
  condition: string
  method: CaptchaMethod
  enabled: boolean
  passRate?: number
  challengesToday?: number
}

export interface CaptchaSettings {
  imageCaptcha: boolean
  sliderCaptcha: boolean
  ttlSeconds: number
  maxAttempts: number
  triggers: CaptchaTrigger[]
}

export async function fetchCaptchaSettings(): Promise<CaptchaSettings> {
  const { data } = await http.get<CaptchaSettings>('/captcha')
  return data
}

export async function updateCaptchaSettings(payload: CaptchaSettings): Promise<CaptchaSettings> {
  const { data } = await http.put<CaptchaSettings>('/captcha', payload)
  return data
}
