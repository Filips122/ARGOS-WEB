'use client';

import { useEffect, useState } from 'react';
import type { ArgosLiveData } from '@/lib/argos-normalizers';

export function useArgosLiveData(refreshMs = 5000) {
  const [data, setData] = useState<ArgosLiveData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    // setInterval dispara pase lo que pase. Sin este guardia, una peticion de
    // 15 s con sondeo cada 5 s deja tres en vuelo a la vez, y cada una lanza
    // dos consultas al indexer: el triple de carga de la que se cree hacer.
    let inFlight = false;

    async function load() {
      if (inFlight) return;
      inFlight = true;
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
      } finally {
        inFlight = false;
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
