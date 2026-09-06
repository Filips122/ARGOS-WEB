/**
 * Puente MCP del lado servidor.
 *
 * La aplicacion web actua como HOST del Model Context Protocol: levanta el
 * servidor MCP de ARGOS (deploy/argos_mcp/server.ts) como proceso hijo, habla
 * con el por stdio y expone sus herramientas al modelo. Es exactamente el mismo
 * servidor y el mismo protocolo que consume Claude Desktop; la unica diferencia
 * es quien hace de cliente.
 *
 *   navegador -> /api/argos/mcp-chat -> [cliente MCP] -> stdio -> servidor MCP
 *                                                                     |
 *                                                        /api/argos/live, sidecar
 *
 * El proceso hijo se reutiliza entre peticiones (arrancarlo cuesta ~1 s) y se
 * reinicia solo si muere.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import path from 'node:path';

export type McpToolSpec = {
  name: string;
  description: string;
  input_schema: { type: 'object'; properties?: Record<string, unknown>; required?: string[] };
};

const SERVER_PATH = path.join(process.cwd(), 'deploy', 'argos_mcp', 'server.ts');

/**
 * El servidor MCP consulta la API de esta misma aplicacion. Por defecto apunta
 * al puerto en el que Next se esta sirviendo, para que no haya que configurar
 * nada al cambiar de puerto (3000 en desarrollo, 3010 en las pruebas).
 */
function webUrl(): string {
  if (process.env.ARGOS_WEB_URL) return process.env.ARGOS_WEB_URL;
  return `http://127.0.0.1:${process.env.PORT ?? 3000}`;
}

type Session = { client: Client; tools: McpToolSpec[] };

// Next reutiliza el modulo entre peticiones, pero en desarrollo lo recarga en
// caliente; el globalThis evita dejar procesos hijo huerfanos en cada recarga.
const store = globalThis as typeof globalThis & {
  __argosMcp?: Promise<Session> | null;
  __argosMcpCleanup?: boolean;
};

/**
 * El proceso hijo no muere solo si al servidor Next lo matan: se ha comprobado
 * que sobrevive y deja un huerfano. Se cierra explicitamente al salir y ante
 * Ctrl+C. Contra un SIGKILL no hay defensa posible desde aqui.
 */
function registerCleanup() {
  if (store.__argosMcpCleanup) return;
  store.__argosMcpCleanup = true;
  const stop = () => {
    void closeMcpSession();
  };
  process.once('exit', stop);
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}

async function connect(): Promise<Session> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_PATH],
    env: {
      ...(process.env as Record<string, string>),
      ARGOS_WEB_URL: webUrl(),
      ARGOS_SCORER_URL: process.env.ARGOS_SCORER_URL ?? 'http://127.0.0.1:8973',
    },
    // Los fallos del hijo salen por la consola del servidor Next; con 'ignore'
    // un arranque roto seria silencioso y solo se veria como chat degradado.
    stderr: 'inherit',
  });

  const client = new Client({ name: 'argos-web-host', version: '1.0.0' });
  await client.connect(transport);

  // Si el hijo muere (crash, reinicio del sidecar), se descarta la sesion para
  // que la siguiente peticion levante una limpia en vez de fallar siempre.
  client.onclose = () => {
    if (store.__argosMcp) store.__argosMcp = null;
  };

  registerCleanup();

  const { tools } = await client.listTools();
  const specs: McpToolSpec[] = tools.map((tool) => ({
    name: tool.name,
    description: tool.description ?? tool.title ?? tool.name,
    input_schema: (tool.inputSchema as McpToolSpec['input_schema']) ?? { type: 'object' },
  }));

  return { client, tools: specs };
}

/** Sesion MCP compartida. Arranca el servidor la primera vez que se usa. */
export async function getMcpSession(): Promise<Session> {
  if (!store.__argosMcp) {
    store.__argosMcp = connect().catch((error) => {
      store.__argosMcp = null;
      throw error;
    });
  }
  return store.__argosMcp;
}

/**
 * Invoca una herramienta MCP y aplana su respuesta a texto plano, que es lo que
 * espera un bloque tool_result. Un error de la herramienta no se lanza: se
 * devuelve como texto para que el modelo pueda explicarlo o reintentar con
 * otros argumentos.
 */
export async function callMcpTool(
  name: string,
  args: Record<string, unknown>
): Promise<{ text: string; isError: boolean }> {
  const { client } = await getMcpSession();
  try {
    const result = await client.callTool({ name, arguments: args });
    const body = ((result.content ?? []) as { type: string; text?: string }[])
      .filter((block) => block.type === 'text')
      .map((block) => block.text ?? '')
      .join('\n');
    return { text: body || '(la herramienta no devolvio contenido)', isError: Boolean(result.isError) };
  } catch (error) {
    return {
      text: `La herramienta ${name} fallo: ${error instanceof Error ? error.message : String(error)}`,
      isError: true,
    };
  }
}

/** Cierra la sesion. Solo se usa en pruebas para no dejar el proceso vivo. */
export async function closeMcpSession(): Promise<void> {
  const session = store.__argosMcp;
  store.__argosMcp = null;
  if (!session) return;
  try {
    (await session).client.onclose = undefined;
    await (await session).client.close();
  } catch {
    // el hijo ya estaba muerto
  }
}
