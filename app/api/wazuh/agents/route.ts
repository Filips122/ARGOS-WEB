import { NextResponse } from 'next/server';
import { wazuhApiGet } from '@/lib/wazuh';

export const runtime = 'nodejs';

export async function GET() {
  try {
    const data = await wazuhApiGet('/agents?limit=100');

    return NextResponse.json({
      ok: true,
      source: 'wazuh-manager',
      data,
    });
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        source: 'wazuh-manager',
        error: error instanceof Error ? error.message : 'Unknown Wazuh API error',
      },
      { status: 500 }
    );
  }
}
