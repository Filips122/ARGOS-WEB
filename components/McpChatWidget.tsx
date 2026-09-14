'use client';

import { useEffect, useRef, useState } from 'react';
import { MiniMarkdown } from '@/components/MiniMarkdown';
import { copyReport, downloadMarkdown, printReportAsPdf } from '@/lib/report-export';

type ToolTrace = { name: string; args: Record<string, unknown>; ms: number; chars: number; isError: boolean };

type Engine = 'cli' | 'api' | 'keywords';

type ChatMessage = {
  role: 'user' | 'assistant';
  content: string;
  engine?: Engine;
  toolCalls?: ToolTrace[];
  degraded?: string;
};

type EngineStatus = {
  engine: Engine;
  model?: string;
  auth?: string;
  tools: number;
  reason?: string;
};

const KEYWORD_HINT =
  'Consulta determinista sobre las alertas cargadas. No es un modelo de lenguaje: reconoce palabras clave. Prueba con "ultimos 5 critical" o "resumen de severidad".';

const CLAUDE_HINT =
  'Conectado a Claude sobre las herramientas MCP de ARGOS. Pregunta en lenguaje natural: puede encadenar consultas, cruzar alertas con riesgo de IP y simular bloqueos en seco.';

/**
 * La cabecera dice que motor RESPONDE, no como se llama el boton. Con el motor
 * de reglas no interviene ningun MCP, asi que ponerle "MCP" seria mentir sobre
 * el origen de la respuesta.
 */
const ENGINE_LABEL: Record<Engine, string> = {
  cli: 'MCP · suscripcion',
  api: 'MCP · clave de API',
  keywords: 'SIN MCP · reglas',
};

function formatArgs(args: Record<string, unknown>) {
  const entries = Object.entries(args ?? {});
  if (entries.length === 0) return '';
  return entries.map(([key, value]) => `${key}=${String(value)}`).join(', ');
}

/**
 * Copiar, .md y PDF sobre una respuesta del asistente.
 *
 * Solo en respuestas del asistente: exportar la propia pregunta no tiene
 * sentido. La traza de herramientas viaja al PDF y al Markdown, porque un
 * informe suelto que no dice de dónde salen sus cifras no es defendible.
 */
function MessageActions({ message }: { message: ChatMessage }) {
  const [done, setDone] = useState<string | null>(null);

  const meta = {
    tools: message.toolCalls?.map((call) => ({ name: call.name, args: call.args })),
    engine: message.engine,
  };

  function flash(label: string) {
    setDone(label);
    window.setTimeout(() => setDone(null), 1800);
  }

  return (
    <div className="mcpChatActions">
      <button
        type="button"
        onClick={async () => flash((await copyReport(message.content)) ? 'Copiado' : 'No se pudo copiar')}
      >
        Copiar
      </button>
      <button
        type="button"
        onClick={() => {
          downloadMarkdown(message.content, meta);
          flash('Descargado .md');
        }}
      >
        .md
      </button>
      <button
        type="button"
        title="Abre el diálogo de impresión; elige «Guardar como PDF»"
        onClick={() =>
          flash(
            printReportAsPdf(message.content, meta)
              ? 'Abriendo impresión'
              : 'Bloqueado por el navegador'
          )
        }
      >
        PDF
      </button>
      {done && <em>{done}</em>}
    </div>
  );
}

export function McpChatWidget() {
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<EngineStatus | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  // Identificador de la conversacion del CLI: permite preguntas de seguimiento
  // ("y esa IP?") sin reenviar todo el historial.
  const [sessionId, setSessionId] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  // Se pregunta al servidor que motor va a contestar antes de escribir nada,
  // para no prometer lenguaje natural si no hay clave configurada.
  useEffect(() => {
    if (!open || status) return;
    let cancelled = false;
    fetch('/api/argos/mcp-chat')
      .then((response) => response.json())
      .then((payload) => {
        if (cancelled) return;
        const engine: Engine =
          payload.engine === 'cli' || payload.engine === 'api' ? payload.engine : 'keywords';
        const next: EngineStatus = {
          engine,
          model: payload.model,
          auth: payload.auth,
          tools: Number(payload.tools ?? 0),
          reason: payload.reason,
        };
        setStatus(next);
        setMessages((current) =>
          current.length > 0
            ? current
            : [
                {
                  role: 'assistant',
                  content: next.engine === 'keywords' ? KEYWORD_HINT : CLAUDE_HINT,
                  engine: next.engine,
                },
              ]
        );
      })
      .catch(() => {
        if (cancelled) return;
        setStatus({ engine: 'keywords', tools: 0, reason: 'No se pudo consultar el estado' });
      });
    return () => {
      cancelled = true;
    };
  }, [open, status]);

  async function sendMessage() {
    const message = input.trim();
    if (!message || loading) return;

    const history = messages.map(({ role, content }) => ({ role, content }));

    setMessages((current) => [...current, { role: 'user', content: message }]);
    setInput('');
    setLoading(true);

    try {
      const response = await fetch('/api/argos/mcp-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, history, sessionId }),
      });
      const payload = await response.json();

      if (!response.ok || !payload.ok) {
        throw new Error(payload.error ?? 'La consulta fallo');
      }

      if (payload.sessionId) setSessionId(String(payload.sessionId));

      setMessages((current) => [
        ...current,
        {
          role: 'assistant',
          content: String(payload.answer ?? ''),
          engine: payload.engine === 'cli' || payload.engine === 'api' ? payload.engine : 'keywords',
          toolCalls: Array.isArray(payload.toolCalls) ? payload.toolCalls : undefined,
          degraded: payload.degraded ? String(payload.degraded) : undefined,
        },
      ]);
    } catch (error) {
      setMessages((current) => [
        ...current,
        {
          role: 'assistant',
          content: error instanceof Error ? `No he podido consultar ARGOS: ${error.message}` : 'No he podido consultar ARGOS.',
        },
      ]);
    } finally {
      setLoading(false);
      window.setTimeout(() => inputRef.current?.focus(), 0);
    }
  }

  const usingClaude = status?.engine === 'cli' || status?.engine === 'api';

  return (
    <div className="mcpChatDock" aria-live="polite">
      {open && (
        <section className="mcpChatPanel" aria-label="Asistente MCP de ARGOS">
          <div className="mcpChatHeader">
            <div>
              <span>
                {status ? ENGINE_LABEL[status.engine] : 'MCP'}
                {usingClaude ? ` · ${status?.tools ?? 0} herramientas` : ''}
              </span>
              <b>ARGOS SOC Assistant</b>
            </div>
            <button type="button" onClick={() => setOpen(false)} aria-label="Cerrar el asistente">
              x
            </button>
          </div>
          <div className="mcpChatMessages">
            {messages.map((message, index) => (
              <div key={`${message.role}-${index}`} className={`mcpChatMessage ${message.role}`}>
                {message.degraded && (
                  <p className="mcpChatDegraded">
                    Motor preferente no disponible, respondido con el de respaldo ({message.degraded}).
                  </p>
                )}
                {message.toolCalls && message.toolCalls.length > 0 && (
                  <ul className="mcpChatTrace">
                    {message.toolCalls.map((call, callIndex) => (
                      <li key={`${call.name}-${callIndex}`} className={call.isError ? 'err' : undefined}>
                        <code>{call.name}</code>
                        {formatArgs(call.args) && <em>({formatArgs(call.args)})</em>}
                        <span>{(call.ms / 1000).toFixed(1)} s</span>
                      </li>
                    ))}
                  </ul>
                )}
                <MiniMarkdown text={message.content} />
                {message.role === 'assistant' && message.content.trim().length > 0 && (
                  <MessageActions message={message} />
                )}
              </div>
            ))}
            {loading && (
              <div className="mcpChatMessage assistant">
                <p>{usingClaude ? 'Consultando las herramientas MCP...' : 'Consultando alertas...'}</p>
              </div>
            )}
          </div>
          <form
            className="mcpChatForm"
            onSubmit={(event) => {
              event.preventDefault();
              sendMessage();
            }}
          >
            <input
              ref={inputRef}
              value={input}
              onChange={(event) => setInput(event.target.value)}
              placeholder={usingClaude ? 'Ej: que IP deberia bloquear y por que?' : 'Ej: ultimos 5 critical'}
              aria-label="Pregunta al asistente MCP"
            />
            <button type="submit" disabled={loading || !input.trim()}>
              Send
            </button>
          </form>
        </section>
      )}

      <button
        type="button"
        className="mcpChatButton"
        onClick={() => {
          setOpen((current) => !current);
          window.setTimeout(() => inputRef.current?.focus(), 0);
        }}
        aria-label={open ? 'Cerrar el asistente MCP' : 'Abrir el asistente MCP'}
      >MCP</button>
    </div>
  );
}
