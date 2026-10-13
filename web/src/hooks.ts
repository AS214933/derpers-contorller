import { useCallback, useEffect, useRef, useState } from "react";
import { request, errorText } from "./api";

export function useResource<T>(path: string | null, refreshInterval = 0) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  const active = useRef(0);
  useEffect(() => {
    if (!path) {
      setLoading(false);
      return;
    }
    const ctrl = new AbortController();
    const id = ++active.current;
    setLoading(true);
    setError("");
    request<T>(path, { signal: ctrl.signal })
      .then((value) => {
        if (active.current === id) setData(value);
      })
      .catch((e) => {
        if (!ctrl.signal.aborted && active.current === id)
          setError(errorText(e));
      })
      .finally(() => {
        if (active.current === id && !ctrl.signal.aborted) setLoading(false);
      });
    return () => ctrl.abort();
  }, [path, tick]);
  useEffect(() => {
    if (!refreshInterval || !path) return;
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") reload();
    }, refreshInterval);
    return () => clearInterval(timer);
  }, [path, refreshInterval, reload]);
  return { data, loading, error, reload };
}
