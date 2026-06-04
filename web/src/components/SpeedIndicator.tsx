import { formatSpeed } from '../lib/utils'

interface SpeedIndicatorProps {
  upload: number
  download: number
}

export default function SpeedIndicator({ upload, download }: SpeedIndicatorProps) {
  return (
    <div className="flex gap-4 text-sm">
      <div className="flex items-center gap-2">
        <span className="text-blue-400">↑</span>
        <span className="font-mono">{formatSpeed(upload)}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-green-400">↓</span>
        <span className="font-mono">{formatSpeed(download)}</span>
      </div>
    </div>
  )
}
