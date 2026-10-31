'use client';

import { useEffect, useState } from 'react';

type State<T> = { data: T | null; error: Error | null };

/** Runs `load` when `key` changes; `key: null` skips loading. Ignores responses that arrive after the key moved on. */
export function useApi<T>(key: string | null, load: () => Promise<T>): State<T> & { loading: boolean } {
  const [state, setState] = useState<State<T> & { key: string | null }>({ data: null, error: null, key: null });
  useEffect(() => {
    if (key === null) return;
    let current = true;
    load().then(
      (data) => current && setState({ data, error: null, key }),
      (error: Error) => current && setState({ data: null, error, key }),
    );
    return () => { current = false; };
    // `load` is recreated each render; `key` captures everything it depends on.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  const settled = state.key === key;
  return { data: settled ? state.data : null, error: settled ? state.error : null, loading: key !== null && !settled };
}
