import { describe, expect, it } from 'vitest'
import { isDeletableCronFile } from './cronContextMenu'

describe('cron context-menu safety', () => {
  it('only permits independent files in known cron directories', () => {
    expect(isDeletableCronFile('/etc/cron.d/lovelyres-task')).toBe(true)
    expect(isDeletableCronFile('/etc/cron.daily/cleanup')).toBe(true)
    expect(isDeletableCronFile('/etc/crontab')).toBe(false)
    expect(isDeletableCronFile('/etc/cron.d/../crontab')).toBe(false)
    expect(isDeletableCronFile('/tmp/task')).toBe(false)
  })
})
