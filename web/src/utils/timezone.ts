const TIMEZONE_KEY = 'sftpxy-timezone'

export function getTimezone(): string {
  return localStorage.getItem(TIMEZONE_KEY) || Intl.DateTimeFormat().resolvedOptions().timeZone || 'Asia/Shanghai'
}

export function setTimezone(tz: string): void {
  localStorage.setItem(TIMEZONE_KEY, tz)
}

export function formatTime(isoString: string | null | undefined): string {
  if (!isoString) return '--'
  try {
    const tz = getTimezone()
    const date = new Date(isoString)
    return date.toLocaleString('zh-CN', {
      timeZone: tz,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    })
  } catch {
    return isoString
  }
}

export function getCommonTimezones(): { label: string; value: string }[] {
  return [
    { label: '亚洲/上海 (UTC+8)', value: 'Asia/Shanghai' },
    { label: '亚洲/东京 (UTC+9)', value: 'Asia/Tokyo' },
    { label: '亚洲/首尔 (UTC+9)', value: 'Asia/Seoul' },
    { label: '亚洲/新加坡 (UTC+8)', value: 'Asia/Singapore' },
    { label: '亚洲/加尔各答 (UTC+5:30)', value: 'Asia/Kolkata' },
    { label: '亚洲/迪拜 (UTC+4)', value: 'Asia/Dubai' },
    { label: '欧洲/伦敦 (UTC+0/+1)', value: 'Europe/London' },
    { label: '欧洲/柏林 (UTC+1/+2)', value: 'Europe/Berlin' },
    { label: '欧洲/莫斯科 (UTC+3)', value: 'Europe/Moscow' },
    { label: '美洲/纽约 (UTC-5/-4)', value: 'America/New_York' },
    { label: '美洲/芝加哥 (UTC-6/-5)', value: 'America/Chicago' },
    { label: '美洲/洛杉矶 (UTC-8/-7)', value: 'America/Los_Angeles' },
    { label: '太平洋/奥克兰 (UTC+12/+13)', value: 'Pacific/Auckland' },
    { label: '澳大利亚/悉尼 (UTC+10/+11)', value: 'Australia/Sydney' },
    { label: 'UTC', value: 'UTC' }
  ]
}
