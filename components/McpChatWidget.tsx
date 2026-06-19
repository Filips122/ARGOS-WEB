'use client';

import { useRef, useState } from 'react';

type ChatMessage = {
  role: 'user' | 'assistant';
  content: string;
};

const initialMessages: ChatMessage[] = [
  {
    role: 'assistant',
    content: 'MCP SOC listo. Preguntame por alertas, severidad o clasificacion IA.',
  },
];

export function McpChatWidget() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>(initialMessages);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);

  async function sendMessage() {
    const message = input.trim();
    if (!message || loading) return;

    setMessages((current) => [...current, { role: 'user', content: message }]);
    setInput('');
    setLoading(true);

    try {
      const response = await fetch('/api/argos/mcp-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message }),
      });
      const payload = await response.json();

      if (!response.ok || !payload.ok) {
        throw new Error(payload.error ?? 'MCP query failed');
      }

      setMessages((current) => [...current, { role: 'assistant', content: String(payload.answer ?? '') }]);
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

  return (
    <div className="mcpChatDock" aria-live="polite">
      {open && (
        <section className="mcpChatPanel" aria-label="Chat MCP ARGOS">
          <div className="mcpChatHeader">
            <div>
              <span>MCP</span>
              <b>ARGOS SOC Assistant</b>
            </div>
            <button type="button" onClick={() => setOpen(false)} aria-label="Cerrar chat MCP">
              x
            </button>
          </div>
          <div className="mcpChatMessages">
            {messages.map((message, index) => (
              <div key={`${message.role}-${index}`} className={`mcpChatMessage ${message.role}`}>
                {message.content.split('\n').map((line, lineIndex) => (
                  <p key={lineIndex}>{line}</p>
                ))}
              </div>
            ))}
            {loading && <div className="mcpChatMessage assistant"><p>Consultando alertas...</p></div>}
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
              placeholder="Ej: ultimos 5 critical"
              aria-label="Pregunta al MCP de ARGOS"
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
        aria-label={open ? 'Cerrar chat MCP' : 'Abrir chat MCP'}
      >
        MCP
      </button>
    </div>
  );
}
