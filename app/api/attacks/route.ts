import { NextResponse } from 'next/server';
import { attacks, agentHealth, kpis } from '@/lib/mock-data';

export async function GET() {
  return NextResponse.json({
    project: 'ARGOS-SOC IA',
    mode: 'mock',
    sources: ['Wazuh', 'Suricata', 'Zeek', 'MCP Agents', 'AI Risk Engine'],
    attacks,
    agentHealth,
    kpis,
  });
}
