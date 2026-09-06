'use client';

import { useEffect, useRef, useState } from 'react';

type ToolTrace = { name: string; args: Record<string, unknown>; ms: number; chars: number; isError: boolean };

type ChatMessage = {
  role: 'user' | 'assistant';
  content: string;
  engine?: 'claude' | 'keywords';
  toolCalls?: ToolTrace[];
};

type EngineStatus = {
  engine: 'claude' | 'keywords';
  model?: string;
  tools: number;
  reason?: string;
};

const KEYWORD_HINT =
  'Consulta determinista sobre las alertas cargadas. No es un modelo de lenguaje: reconoce palabras clave. Prueba con "ultimos 5 critical" o "resumen de severidad".';

const CLAUDE_HINT =
  'Conectado a Claude sobre las herramientas MCP de ARGOS. Pregunta en lenguaje natural: puede encadenar consultas, cruzar alertas con riesgo de IP y simular bloqueos en seco.';

function formatArgs(args: Record<string, unknown>) {
  const entries = Object.entries(args ?? {});
  if (entries.length === 0) return '';
  return entries.map(([key, value]) => `${key}=${String(value)}`).join(', ');
}

export function McpChatWidget() {
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<EngineStatus | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
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
        const next: EngineStatus = {
          engine: payload.engine === 'claude' ? 'claude' : 'keywords',
          model: payload.model,
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
                  content: next.engine === 'claude' ? CLAUDE_HINT : KEYWORD_HINT,
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
        body: JSON.stringify({ message, history }),
      });
      const payload = await response.json();

      if (!response.ok || !payload.ok) {
        throw new Error(payload.error ?? 'La consulta fallo');
      }

      setMessages((current) => [
        ...current,
        {
          role: 'assistant',
          content: String(payload.answer ?? ''),
          engine: payload.engine === 'claude' ? 'claude' : 'keywords',
          toolCalls: Array.isArray(payload.toolCalls) ? payload.toolCalls : undefined,
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

  const usingClaude = status?.engine === 'claude';

  return (
    <div className="mcpChatDock" aria-live="polite">
      {open && (
        <section className="mcpChatPanel" aria-label="Consulta de alertas ARGOS">
          <div className="mcpChatHeader">
            <div>
              <span>{usingClaude ? `MCP · ${status?.tools ?? 0} herramientas` : 'CONSULTA'}</span>
              <b>ARGOS SOC Assistant</b>
            </div>
            <button type="button" onClick={() => setOpen(false)} aria-label="Cerrar consulta">
              x
            </button>
          </div>
          <div className="mcpChatMessages">
            {messages.map((message, index) => (
              <div key={`${message.role}-${index}`} className={`mcpChatMessage ${message.role}`}>
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
                {message.content.split('\n').map((line, lineIndex) => (
                  <p key={lineIndex}>{line}</p>
                ))}
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
              aria-label="Consulta sobre las alertas"
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
        aria-label={open ? 'Cerrar consulta' : 'Abrir consulta de alertas'}
      >CONSULTA</button>
    </div>
  );
}
