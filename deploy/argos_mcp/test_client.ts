/**
 * Cliente MCP de prueba: habla el protocolo real contra el servidor de ARGOS,
 * lista sus herramientas y las invoca. Sirve como comprobacion de que el
 * servidor cumple MCP sin depender de Claude Desktop ni de una API key.
 *
 *   node deploy/argos_mcp/test_client.ts
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import path from 'node:path';

const SERVER = path.join(process.cwd(), 'deploy', 'argos_mcp', 'server.ts');

function preview(result: any, lines = 6): string {
  const body = (result.content ?? [])
    .filter((c: any) => c.type === 'text')
    .map((c: any) => c.text)
    .join('\n');
  const chunk = body.split('\n').slice(0, lines).join('\n      ');
  return `      ${chunk}${body.split('\n').length > lines ? '\n      ...' : ''}`;
}

async function main() {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER],
    // 3000 es donde sirve `npm run dev`, igual que en .mcp.json. Antes ponia
    // 3010, que era un puerto de pruebas: el cliente fallaba con "fetch failed"
    // contra una web que si estaba levantada, en otro puerto.
    env: { ...process.env, ARGOS_WEB_URL: process.env.ARGOS_WEB_URL ?? 'http://127.0.0.1:3000' },
  });

  const client = new Client({ name: 'argos-mcp-test', version: '1.0.0' });
  await client.connect(transport);
  console.log('conectado al servidor MCP\n');

  const { tools } = await client.listTools();
  console.log(`HERRAMIENTAS EXPUESTAS: ${tools.length}\n`);
  for (const tool of tools) {
    const params = Object.keys(tool.inputSchema?.properties ?? {});
    console.log(`  ${tool.name}`);
    console.log(`    ${tool.description?.slice(0, 96)}...`);
    console.log(`    parametros: ${params.length ? params.join(', ') : '(ninguno)'}\n`);
  }

  const calls: [string, Record<string, unknown>][] = [
    ['estado_plataforma', {}],
    ['resumen_amenazas', {}],
    ['buscar_alertas', { severidad: 'low', limite: 2 }],
    ['vulnerabilidades_explotadas', {}],
    ['estado_modelos', {}],
  ];

  for (const [name, args] of calls) {
    console.log(`\n${'='.repeat(66)}\nLLAMADA: ${name}(${JSON.stringify(args)})`);
    try {
      const result = await client.callTool({ name, arguments: args });
      console.log(result.isError ? '  -> ERROR' : '  -> ok');
      console.log(preview(result));
    } catch (error) {
      console.log(`  -> EXCEPCION: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  await client.close();
  console.log(`\n${'='.repeat(66)}\ncliente cerrado`);
}

main().catch((error) => {
  console.error('fallo:', error);
  process.exit(1);
});
