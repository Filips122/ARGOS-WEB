import { NextResponse } from 'next/server';
import { buildArgosLiveData } from '@/lib/argos-normalizers';
import { wazuhApiGet } from '@/lib/wazuh';
import { getRecentWazuhAlerts, getWazuhAlertsCount } from '@/lib/wazuh-indexer';

export const runtime = 'nodejs';

function getReason(error: unknown) {
  return error instanceof Error ? error.message : 'Unknown error';
}

async function getMonthlyAlerts() {
  try {
    return {
      data: await getRecentWazuhAlerts(10000, 'now-30d'),
      error: null,
    };
  } catch (error) {
    return {
      data: null,
      error: getReason(error),
    };
  }
}

export async function GET() {
  const [agents, manager, alerts, events24h] = await Promise.allSettled([
    wazuhApiGet('/agents?limit=100'),
    wazuhApiGet('/manager/info'),
    getMonthlyAlerts(),
    getWazuhAlertsCount('now-24h'),
  ]);

  const liveData = buildArgosLiveData({
    manager: manager.status === 'fulfilled' ? manager.value : null,
    agents: agents.status === 'fulfilled' ? agents.value : null,
    alerts: alerts.status === 'fulfilled' ? alerts.value.data : null,
    events24h: events24h.status === 'fulfilled' ? events24h.value : null,
    errors: {
      manager: manager.status === 'rejected' ? getReason(manager.reason) : null,
      agents: agents.status === 'rejected' ? getReason(agents.reason) : null,
      alerts: alerts.status === 'rejected' ? getReason(alerts.reason) : alerts.value.error,
    },
  });

  return NextResponse.json(liveData);
}
