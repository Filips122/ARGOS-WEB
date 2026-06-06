import { NextRequest, NextResponse } from 'next/server';
import { getAllRecentWazuhAlerts, getRecentWazuhAlerts } from '@/lib/wazuh-indexer';

export const runtime = 'nodejs';

export async function GET(request: NextRequest) {
  try {
    const limit = Number(request.nextUrl.searchParams.get('limit') ?? 10000);
    const from = request.nextUrl.searchParams.get('from') ?? 'now-30d';
    const all = request.nextUrl.searchParams.get('all') === 'true';
    const data = all ? await getAllRecentWazuhAlerts(from) : await getRecentWazuhAlerts(limit, from);

    return NextResponse.json({
      ok: true,
      source: 'wazuh-indexer',
      data,
    });
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        source: 'wazuh-indexer',
        error: error instanceof Error ? error.message : 'Unknown Wazuh Indexer error',
      },
      { status: 500 }
    );
  }
}
