import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'ARGOS-SOC IA',
  description: 'Global Threat Monitoring for SIEM, IDS/IPS, Wazuh, MCP Agents and AI risk scoring.',
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="es">
      <body>{children}</body>
    </html>
  );
}
