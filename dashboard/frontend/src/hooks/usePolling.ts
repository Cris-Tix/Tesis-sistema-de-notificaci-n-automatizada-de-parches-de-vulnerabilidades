import { useEffect, useRef } from 'react'

export function usePolling(callback: () => void, interval = 30_000) {
  const fn = useRef(callback)
  fn.current = callback

  useEffect(() => {
    fn.current()
    const id = setInterval(() => fn.current(), interval)
    return () => clearInterval(id)
  }, [interval])
}
