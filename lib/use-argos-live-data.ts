'use client';

import { useEffect, useState } from 'react';
import type { ArgosLiveData } from '@/lib/argos-normalizers';

export function useArgosLiveData(refreshMs = 5000) {
  const [data, setData] = useState<ArgosLiveData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const response = await fetch('/api/argos/live', {
          cache: 'no-store',
        });
        const json = await response.json();

        if (!response.ok || !json.ok) {
          throw new Error(json.error ?? 'Failed to load ARGOS live data');
        }

        if (!cancelled) {
          setData(json);
          setError(null);
          setLoading(false);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Unknown ARGOS live error');
          setLoading(false);
        }
      }
    }

    load();
    const interval = window.setInterval(load, refreshMs);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [refreshMs]);

  return { data, error, loading };
}
