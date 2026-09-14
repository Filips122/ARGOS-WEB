/**
 * Motor de suscripcion: responde usando el CLI de Claude Code en modo no
 * interactivo, con el servidor MCP de ARGOS cargado.
 *
 * A diferencia del motor de API, este NO necesita ANTHROPIC_API_KEY: usa la
 * sesion ya iniciada del CLI, es decir, la suscripcion del usuario. Es la unica
 * via por la que una suscripcion puede alimentar la aplicacion, porque no
 * expone ninguna credencial programatica.
 *
 *   navegador -> /api/argos/mcp-chat -> claude -p (stdio) -> servidor MCP ARGOS
 *
 * SUPERFICIE DE ATAQUE. Este endpoint lanza un agente en la maquina. Se acota:
 *  - --strict-mcp-config: solo el servidor MCP de ARGOS, ninguno mas.
 *  - --allowedTools: solo las siete herramientas de solo lectura.
 *  - --disallowedTools: se niegan explicitamente las de escritura y ejecucion.
 *  - --permission-prompts none: nadie contesta prompts, luego se deniegan.
 * Aun asi, NO expongas la aplicacion fuera de localhost con este motor activo.
 */

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** Las siete herramientas del servidor MCP, con el prefijo que usa el CLI. */
const MCP_TOOLS = [
  'estado_plataforma',
  'buscar_alertas',
  'riesgo_de_ip',
  'resumen_amenazas',
  'vulnerabilidades_explotadas',
  'simular_bloqueo',
  'estado_modelos',
].map((name) => `mcp__argos__${name}`);

/** Cinturon y tirantes: aunque la lista blanca ya las excluye. */
const BLOCKED_TOOLS = ['Bash', 'Write', 'Edit', 'NotebookEdit', 'WebFetch', 'WebSearch', 'Task'];

const TIMEOUT_MS = Number(process.env.ARGOS_CLAUDE_TIMEOUT_MS ?? 120_000);

/**
 * Cada invocacion levanta un agente completo, medido en ~300-500 MB. Sin tope,
 * pulsar Enviar varias veces seguidas tumbaria la maquina. Al superarlo la
 * peticion cae al motor de reglas, que responde igualmente.
 */
const MAX_CONCURRENT = Number(process.env.ARGOS_CLAUDE_MAX_CONCURRENT ?? 2);
let running = 0;

export type CliToolTrace = { name: string; args: Record<string, unknown>; ms: number; chars: number; isError: boolean };

export type CliAnswer = {
  answer: string;
  toolCalls: CliToolTrace[];
  sessionId: string | null;
  turns: number;
  /** Coste a precio de lista. Con suscripcion no se factura: consume plan. */
  listCostUsd: number | null;
  model: string;
};

// ---------------------------------------------------------------------------
// Localizacion del binario
// ---------------------------------------------------------------------------

function newestExtensionBinary(): string | null {
  const roots = [
    path.join(os.homedir(), '.vscode', 'extensions'),
    path.join(os.homedir(), '.vscode-insiders', 'extensions'),
    path.join(os.homedir(), '.cursor', 'extensions'),
  ];
  const found: { version: number[]; file: string }[] = [];

  for (const root of roots) {
    let entries: string[];
    try {
      entries = fs.readdirSync(root);
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.startsWith('anthropic.claude-code-')) continue;
      const match = entry.match(/(\d+)\.(\d+)\.(\d+)/);
      for (const name of ['claude.exe', 'claude']) {
        const file = path.join(root, entry, 'resources', 'native-binary', name);
        if (fs.existsSync(file)) {
          found.push({ version: match ? match.slice(1, 4).map(Number) : [0, 0, 0], file });
          break;
        }
      }
    }
  }

  if (found.length === 0) return null;
  // La carpeta lleva la version en el nombre y conviven varias tras actualizar:
  // se coge la mas nueva en vez de fijar una ruta que caducara.
  found.sort((a, b) => b.version[0] - a.version[0] || b.version[1] - a.version[1] || b.version[2] - a.version[2]);
  return found[0].file;
}

function onPath(): string | null {
  const names = process.platform === 'win32' ? ['claude.exe', 'claude.cmd', 'claude'] : ['claude'];
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!dir) continue;
    for (const name of names) {
      const file = path.join(dir, name);
      if (fs.existsSync(file)) return file;
    }
  }
  return null;
}

let resolved: string | null | undefined;

/** Ruta del CLI, o null si no esta instalado. Se resuelve una sola vez. */
export function findClaudeCli(): string | null {
  if (resolved !== undefined) return resolved;

  const override = process.env.ARGOS_CLAUDE_CLI;
  if (override && fs.existsSync(override)) {
    resolved = override;
    return resolved;
  }

  const home = path.join(os.homedir(), '.local', 'bin', process.platform === 'win32' ? 'claude.exe' : 'claude');
  resolved = onPath() ?? (fs.existsSync(home) ? home : null) ?? newestExtensionBinary();
  return resolved;
}

// ---------------------------------------------------------------------------
// Ficheros de apoyo
// ---------------------------------------------------------------------------

/**
 * Config MCP propia en vez de reutilizar .mcp.json del repositorio: asi el
 * servidor apunta al puerto en el que Next se esta sirviendo de verdad, y
 * --strict-mcp-config garantiza que no se cuele ningun otro servidor.
 */
function writeSupportFiles(systemPrompt: string): { mcpConfig: string; promptFile: string } {
  const dir = path.join(os.tmpdir(), 'argos-chat');
  fs.mkdirSync(dir, { recursive: true });

  const webUrl = process.env.ARGOS_WEB_URL ?? `http://127.0.0.1:${process.env.PORT ?? 3000}`;
  const config = {
    mcpServers: {
      argos: {
        command: process.execPath,
        args: [path.join(process.cwd(), 'deploy', 'argos_mcp', 'server.ts')],
        env: {
          ARGOS_WEB_URL: webUrl,
          ARGOS_SCORER_URL: process.env.ARGOS_SCORER_URL ?? 'http://127.0.0.1:8973',
        },
      },
    },
  };

  const mcpConfig = path.join(dir, 'mcp.json');
  const promptFile = path.join(dir, 'system.txt');
  fs.writeFileSync(mcpConfig, JSON.stringify(config, null, 2), 'utf8');
  fs.writeFileSync(promptFile, systemPrompt, 'utf8');
  return { mcpConfig, promptFile };
}

// ---------------------------------------------------------------------------
// Ejecucion
// ---------------------------------------------------------------------------

type Pending = { name: string; args: Record<string, unknown>; at: number };

/**
 * Lanza el CLI y traduce su flujo NDJSON a la misma forma que devuelve el
 * motor de API, para que el widget no tenga que distinguirlos.
 */
export function askClaudeCli(
  message: string,
  systemPrompt: string,
  sessionId?: string | null
): Promise<CliAnswer> {
  const cli = findClaudeCli();
  if (!cli) return Promise.reject(new Error('No se encuentra el CLI de Claude Code'));
  if (running >= MAX_CONCURRENT) {
    return Promise.reject(new Error(`Ya hay ${running} consultas en curso; espera a que terminen`));
  }

  const { mcpConfig, promptFile } = writeSupportFiles(systemPrompt);
  const model = process.env.ARGOS_CLAUDE_MODEL ?? 'sonnet';

  const args = [
    '--print',
    '--output-format', 'stream-json',
    '--verbose',
    '--mcp-config', mcpConfig,
    '--strict-mcp-config',
    '--allowedTools', ...MCP_TOOLS,
    '--disallowedTools', ...BLOCKED_TOOLS,
    '--permission-prompts', 'none',
    '--append-system-prompt-file', promptFile,
    '--model', model,
  ];
  if (sessionId) args.push('--resume', sessionId);

  running += 1;
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    running -= 1;
  };

  return new Promise<CliAnswer>((resolve, reject) => {
    // CLAUDECODE se hereda si la web se arranco desde una sesion de Claude
    // Code y confunde al hijo; se limpia junto al resto de marcas de entorno.
    const env = { ...process.env };
    delete env.CLAUDECODE;
    delete env.CLAUDE_CODE_ENTRYPOINT;
    delete env.CLAUDE_CODE_SSE_PORT;

    const child = spawn(cli, args, { cwd: process.cwd(), env, windowsHide: true });

    const toolCalls: CliToolTrace[] = [];
    const pending = new Map<string, Pending>();
    const texts: string[] = [];
    let result: Record<string, unknown> | null = null;
    let stderr = '';
    let buffer = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      release();
      reject(new Error(`El CLI no respondio en ${Math.round(TIMEOUT_MS / 1000)} s`));
    }, TIMEOUT_MS);

    function handle(line: string) {
      let event: any;
      try {
        event = JSON.parse(line);
      } catch {
        return; // avisos del CLI que no son JSON
      }

      if (event.type === 'assistant') {
        for (const block of event.message?.content ?? []) {
          if (block.type === 'tool_use') {
            pending.set(block.id, { name: block.name, args: block.input ?? {}, at: Date.now() });
          } else if (block.type === 'text' && block.text?.trim()) {
            texts.push(block.text);
          }
        }
        return;
      }

      if (event.type === 'user') {
        const content = event.message?.content;
        if (!Array.isArray(content)) return;
        for (const block of content) {
          if (block?.type !== 'tool_result') continue;
          const call = pending.get(block.tool_use_id);
          if (!call) continue;
          pending.delete(block.tool_use_id);
          // Solo se muestran las herramientas de ARGOS: el CLI usa ademas
          // pasos internos (busqueda de esquemas) que no son consultas al SOC.
          if (!call.name.startsWith('mcp__argos__')) continue;
          const body = typeof block.content === 'string' ? block.content : JSON.stringify(block.content ?? '');
          toolCalls.push({
            name: call.name.replace('mcp__argos__', ''),
            args: call.args,
            ms: Date.now() - call.at,
            chars: body.length,
            isError: Boolean(block.is_error),
          });
        }
        return;
      }

      if (event.type === 'result') result = event;
    }

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      buffer += chunk;
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';
      for (const line of lines) if (line.trim()) handle(line.trim());
    });

    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => {
      stderr = (stderr + chunk).slice(-2000);
    });

    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      release();
      reject(error);
    });

    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      release();
      if (buffer.trim()) handle(buffer.trim());

      if (result?.is_error === true || (code !== 0 && !result)) {
        reject(new Error(String(result?.result ?? stderr.trim() ?? `El CLI termino con codigo ${code}`).slice(0, 300)));
        return;
      }

      const answer = String(result?.result ?? texts.join('\n')).trim();
      if (!answer) {
        reject(new Error('El CLI no devolvio ninguna respuesta'));
        return;
      }

      resolve({
        answer,
        toolCalls,
        sessionId: (result?.session_id as string) ?? null,
        turns: Number(result?.num_turns ?? 0),
        listCostUsd: typeof result?.total_cost_usd === 'number' ? result.total_cost_usd : null,
        model,
      });
    });

    // La pregunta viaja por stdin, nunca como argumento: evita el aviso de 3 s
    // del CLI y hace imposible que el texto del usuario se lea como opciones.
    child.stdin.end(message, 'utf8');
  });
}
