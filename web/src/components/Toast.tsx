import { useState, useEffect, createContext, useContext } from 'react'
import { classNames } from '../lib/utils'

interface Toast {
  id: number
  message: string
  type: 'success' | 'error' | 'info'
}

interface ToastContextType {
  showToast: (message: string, type?: 'success' | 'error' | 'info') => void
}

const ToastContext = createContext<ToastContextType | null>(null)

export function useToast() {
  const context = useContext(ToastContext)
  if (!context) throw new Error('useToast must be used within ToastProvider')
  return context
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const showToast = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
    const id = Date.now()
    setToasts((prev) => [...prev, { id, message, type }])
  }

  const removeToast = (id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 space-y-2">
        {toasts.map((toast) => (
          <ToastItem key={toast.id} toast={toast} onRemove={removeToast} />
        ))}
      </div>
    </ToastContext.Provider>
  )
}

function ToastItem({ toast, onRemove }: { toast: Toast; onRemove: (id: number) => void }) {
  useEffect(() => {
    const timer = setTimeout(() => onRemove(toast.id), 4000)
    return () => clearTimeout(timer)
  }, [toast.id, onRemove])

  return (
    <div
      className={classNames(
        'px-4 py-3 rounded-lg shadow-lg border max-w-md animate-slide-in',
        toast.type === 'success' && 'bg-green-900/30 border-green-500 text-green-400',
        toast.type === 'error' && 'bg-red-900/30 border-red-500 text-red-400',
        toast.type === 'info' && 'bg-blue-900/30 border-blue-500 text-blue-400'
      )}
    >
      <div className="flex items-center justify-between gap-4">
        <span>{toast.message}</span>
        <button onClick={() => onRemove(toast.id)} className="hover:opacity-70">
          ✕
        </button>
      </div>
    </div>
  )
}
