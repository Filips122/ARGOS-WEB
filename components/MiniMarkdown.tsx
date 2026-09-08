'use client';

import type { ReactNode } from 'react';

/**
 * Renderizador de Markdown mínimo, sin dependencias.
 *
 * Existe porque el chat pintaba `content.split('\n')` en párrafos sueltos: un
 * informe con encabezados y tablas se veía como una lista de líneas planas y
 * las tablas eran ilegibles. Cubre lo que un informe necesita y nada más:
 * encabezados, listas, tablas, citas, reglas, negrita, cursiva y código.
 *
 * NO interpreta HTML: el texto viene de un modelo de lenguaje y se trata como
 * datos, nunca como marcado. Todo se emite como nodos de React, así que no hay
 * ninguna vía de inyección.
 */

/** Negrita, cursiva y código en línea. Se resuelve por trozos, sin regex global. */
function inline(text: string, key: string): ReactNode[] {
  const out: ReactNode[] = [];
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/g;
  let last = 0;
  let match: RegExpExecArray | null;
  let index = 0;

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > last) out.push(text.slice(last, match.index));
    const token = match[0];
    const id = `${key}-i${index++}`;
    if (token.startsWith('**')) out.push(<b key={id}>{token.slice(2, -2)}</b>);
    else if (token.startsWith('`')) out.push(<code key={id}>{token.slice(1, -1)}</code>);
    else out.push(<i key={id}>{token.slice(1, -1)}</i>);
    last = match.index + token.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function splitRow(line: string): string[] {
  return line.replace(/^\||\|$/g, '').split('|').map((cell) => cell.trim());
}

const isSeparator = (line: string) => /^\|?[\s:|-]+\|[\s:|-]*$/.test(line) && line.includes('-');

export function MiniMarkdown({ text }: { text: string }) {
  const lines = text.split('\n');
  const blocks: ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const key = `b${i}`;

    // Bloque de código cercado
    if (line.trimStart().startsWith('```')) {
      const body: string[] = [];
      i += 1;
      while (i < lines.length && !lines[i].trimStart().startsWith('```')) body.push(lines[i++]);
      i += 1;
      blocks.push(<pre key={key}>{body.join('\n')}</pre>);
      continue;
    }

    // Tabla: cabecera + separador. Sin separador no es tabla.
    if (line.trim().startsWith('|') && i + 1 < lines.length && isSeparator(lines[i + 1])) {
      const head = splitRow(line);
      i += 2;
      const body: string[][] = [];
      while (i < lines.length && lines[i].trim().startsWith('|')) body.push(splitRow(lines[i++]));
      blocks.push(
        <div className="mdTableWrap" key={key}>
          <table>
            <thead>
              <tr>{head.map((cell, c) => <th key={c}>{inline(cell, `${key}-h${c}`)}</th>)}</tr>
            </thead>
            <tbody>
              {body.map((row, r) => (
                <tr key={r}>{row.map((cell, c) => <td key={c}>{inline(cell, `${key}-${r}-${c}`)}</td>)}</tr>
              ))}
            </tbody>
          </table>
        </div>
      );
      continue;
    }

    // Lista, con o sin numeración
    if (/^\s*([-*+]|\d+\.)\s+/.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const items: string[] = [];
      while (i < lines.length && /^\s*([-*+]|\d+\.)\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*([-*+]|\d+\.)\s+/, ''));
        i += 1;
      }
      const children = items.map((item, n) => <li key={n}>{inline(item, `${key}-l${n}`)}</li>);
      blocks.push(ordered ? <ol key={key}>{children}</ol> : <ul key={key}>{children}</ul>);
      continue;
    }

    // Cita
    if (line.trimStart().startsWith('>')) {
      const body: string[] = [];
      while (i < lines.length && lines[i].trimStart().startsWith('>')) {
        body.push(lines[i].replace(/^\s*>\s?/, ''));
        i += 1;
      }
      blocks.push(<blockquote key={key}>{inline(body.join(' '), key)}</blockquote>);
      continue;
    }

    // Regla horizontal
    if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      blocks.push(<hr key={key} />);
      i += 1;
      continue;
    }

    // Encabezado
    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      const level = heading[1].length;
      const content = inline(heading[2], key);
      blocks.push(
        level === 1 ? <h3 key={key}>{content}</h3>
        : level === 2 ? <h4 key={key}>{content}</h4>
        : <h5 key={key}>{content}</h5>
      );
      i += 1;
      continue;
    }

    // Línea en blanco
    if (!line.trim()) {
      i += 1;
      continue;
    }

    // Párrafo: se juntan las líneas seguidas, como en Markdown de verdad.
    const paragraph: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() &&
      !/^(#{1,4}\s|\s*([-*+]|\d+\.)\s|\s*>)/.test(lines[i]) &&
      !lines[i].trim().startsWith('|') &&
      !lines[i].trimStart().startsWith('```')
    ) {
      paragraph.push(lines[i++]);
    }
    blocks.push(<p key={key}>{inline(paragraph.join(' '), key)}</p>);
  }

  return <div className="mdBody">{blocks}</div>;
}
