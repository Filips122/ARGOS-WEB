import { NextResponse } from 'next/server';
import { DatasetStats, streamDatasetRecords, type DatasetRecord } from '@/lib/dataset-export';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const DEFAULT_LIMIT = 50_000;
const MAX_LIMIT = 2_000_000;
// format=json buffers the whole payload, so it stays far below the streaming cap.
const MAX_BUFFERED_LIMIT = 100_000;

function getReason(error: unknown) {
  return error instanceof Error ? error.message : 'Unknown error';
}

function readLimit(value: string | null, max: number) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return Math.min(DEFAULT_LIMIT, max);
  return Math.min(Math.trunc(parsed), max);
}

function filename(extension: string, from: string, to: string) {
  const slug = (from + '_' + to).replace(/[^a-zA-Z0-9-]+/g, '-');
  return 'argos-alerts_' + slug + '.' + extension;
}

export async function GET(request: Request) {
  const params = new URL(request.url).searchParams;
  const from = params.get('from') ?? 'now-30d';
  const to = params.get('to') ?? 'now';
  const format = params.get('format') ?? 'jsonl';
  const includeSimulated = params.get('simulated') === 'include';
  const download = params.get('download') !== '0';

  const keep = (record: DatasetRecord) => includeSimulated || record.is_simulated === 0;

  if (format === 'manifest') {
    const stats = new DatasetStats();
    try {
      for await (const record of streamDatasetRecords({ from, to, limit: readLimit(params.get('limit'), MAX_LIMIT) })) {
        if (keep(record)) stats.add(record);
      }
    } catch (error) {
      return NextResponse.json({ error: getReason(error) }, { status: 502 });
    }
    return NextResponse.json(stats.manifest({ from, to }, new Date().toISOString()), {
      headers: { 'Cache-Control': 'no-store' },
    });
  }

  if (format === 'json') {
    const limit = readLimit(params.get('limit'), MAX_BUFFERED_LIMIT);
    const stats = new DatasetStats();
    const records: DatasetRecord[] = [];
    try {
      for await (const record of streamDatasetRecords({ from, to, limit })) {
        if (!keep(record)) continue;
        stats.add(record);
        records.push(record);
      }
    } catch (error) {
      return NextResponse.json({ error: getReason(error) }, { status: 502 });
    }

    const body = JSON.stringify(
      { manifest: stats.manifest({ from, to }, new Date().toISOString()), records },
      null,
      2
    );
    const headers: Record<string, string> = {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    };
    if (download) headers['Content-Disposition'] = 'attachment; filename="' + filename('json', from, to) + '"';
    return new NextResponse(body, { headers });
  }

  // Default: newline-delimited JSON, streamed so a full-month export never has to
  // be materialised in memory. Read it back with pandas.read_json(path, lines=True).
  const limit = readLimit(params.get('limit'), MAX_LIMIT);
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        for await (const record of streamDatasetRecords({ from, to, limit })) {
          if (keep(record)) controller.enqueue(encoder.encode(JSON.stringify(record) + '\n'));
        }
      } catch (error) {
        controller.enqueue(encoder.encode(JSON.stringify({ argos_export_error: getReason(error) }) + '\n'));
      }
      controller.close();
    },
  });

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-ndjson; charset=utf-8',
    'Cache-Control': 'no-store',
  };
  if (download) headers['Content-Disposition'] = 'attachment; filename="' + filename('jsonl', from, to) + '"';
  return new NextResponse(stream, { headers });
}
