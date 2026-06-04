import { classNames } from '../lib/utils'

interface StatusBadgeProps {
  running: boolean
}

export default function StatusBadge({ running }: StatusBadgeProps) {
  return (
    <span
      className={classNames(
        'inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium',
        running ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'
      )}
    >
      <span
        className={classNames(
          'w-2 h-2 rounded-full',
          running ? 'bg-green-400 animate-pulse' : 'bg-red-400'
        )}
      />
      {running ? '运行中' : '已停止'}
    </span>
  )
}
