/**
 * Exportación de una respuesta del asistente: portapapeles, Markdown y PDF.
 *
 * El PDF se genera con la impresión del navegador ("Guardar como PDF") en vez
 * de con una biblioteca. Es una decisión, no una carencia:
 *
 *  - jsPDF escribe el texto a mano, sin saltos ni tablas: habría que maquetar
 *    el informe a mano y se rompe con cualquier contenido nuevo.
 *  - html2canvas rasteriza: el PDF pesa más, no se puede seleccionar el texto
 *    ni buscar en él, y en una memoria de TFM eso es peor que inútil.
 *  - Un navegador sin cabeza en el servidor son ~300 MB de dependencia para
 *    una función que el navegador ya trae.
 *
 * A cambio, el usuario pasa por el diálogo de impresión. El PDF resultante
 * lleva texto real, seleccionable y con tablas maquetadas por el motor del
 * navegador.
 */

export type ReportMeta = {
  /** Herramientas MCP que produjeron los datos. Es la trazabilidad del informe. */
  tools?: { name: string; args: Record<string, unknown> }[];
  engine?: string;
  model?: string;
};

function stamp(): string {
  return new Date().toLocaleString('es-ES', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function slug(text: string): string {
  const firstLine = text.split('\n').find((line) => line.replace(/[#\s*]/g, '')) ?? 'informe';
  return (
    firstLine
      .replace(/[#*`|]/g, '')
      .trim()
      .slice(0, 48)
      .normalize('NFD')
      // NFD separa el acento de la letra; el filtro de abajo lo descarta.
      .replace(/[^a-zA-Z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .toLowerCase() || 'informe'
  );
}

/** Pie común: sin esto un PDF suelto no dice de dónde salieron sus cifras. */
function footerLines(meta: ReportMeta): string[] {
  const lines = [
    `Generado por ARGOS-SOC IA el ${stamp()}.`,
    'Datos de las alertas cargadas en ese momento, no del histórico completo.',
  ];
  if (meta.tools?.length) {
    lines.push(`Herramientas consultadas: ${meta.tools.map((t) => t.name).join(', ')}.`);
  }
  if (meta.engine) lines.push(`Motor: ${meta.engine}${meta.model ? ` (${meta.model})` : ''}.`);
  lines.push(
    'Dominio de validez: atacantes ruidosos (fuerza bruta, escaneo, spraying). ' +
      'El país de origen es el de la máquina usada, no el del atacante.'
  );
  return lines;
}

export async function copyReport(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Sin permiso de portapapeles (contexto no seguro, por ejemplo): se cae al
    // método antiguo antes de rendirse.
    try {
      const area = document.createElement('textarea');
      area.value = text;
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(area);
      return ok;
    } catch {
      return false;
    }
  }
}

export function downloadMarkdown(text: string, meta: ReportMeta = {}): void {
  const body = [text, '', '---', '', ...footerLines(meta).map((line) => `> ${line}`)].join('\n');
  const blob = new Blob([body], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `argos-${slug(text)}.md`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  // Revocar de inmediato aborta la descarga en algunos navegadores.
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Markdown -> HTML para imprimir. Cubre lo mismo que MiniMarkdown; se duplica
 * a propósito porque aquí el destino es una cadena para otra ventana, no
 * nodos de React, y compartir el árbol obligaría a montar React fuera.
 *
 * Todo el texto se escapa ANTES de aplicar el marcado: el contenido viene de
 * un modelo de lenguaje y se trata como datos.
 */
function markdownToHtml(source: string): string {
  const lines = escapeHtml(source).split('\n');
  const out: string[] = [];
  let i = 0;

  const inline = (text: string) =>
    text
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/(^|[^*])\*([^*]+)\*/g, '$1<em>$2</em>');

  const splitRow = (line: string) => line.replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
  const isSeparator = (line: string) => /^\|?[\s:|-]+\|[\s:|-]*$/.test(line) && line.includes('-');

  while (i < lines.length) {
    const line = lines[i];

    if (line.trim().startsWith('|') && i + 1 < lines.length && isSeparator(lines[i + 1])) {
      const head = splitRow(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].trim().startsWith('|')) rows.push(splitRow(lines[i++]));
      out.push(
        '<table><thead><tr>' +
          head.map((c) => `<th>${inline(c)}</th>`).join('') +
          '</tr></thead><tbody>' +
          rows.map((r) => '<tr>' + r.map((c) => `<td>${inline(c)}</td>`).join('') + '</tr>').join('') +
          '</tbody></table>'
      );
      continue;
    }

    if (/^\s*([-*+]|\d+\.)\s+/.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const items: string[] = [];
      while (i < lines.length && /^\s*([-*+]|\d+\.)\s+/.test(lines[i])) {
        items.push(inline(lines[i].replace(/^\s*([-*+]|\d+\.)\s+/, '')));
        i += 1;
      }
      const tag = ordered ? 'ol' : 'ul';
      out.push(`<${tag}>` + items.map((t) => `<li>${t}</li>`).join('') + `</${tag}>`);
      continue;
    }

    if (line.trimStart().startsWith('&gt;')) {
      const body: string[] = [];
      while (i < lines.length && lines[i].trimStart().startsWith('&gt;')) {
        body.push(lines[i].replace(/^\s*&gt;\s?/, ''));
        i += 1;
      }
      out.push(`<blockquote>${inline(body.join(' '))}</blockquote>`);
      continue;
    }

    if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      out.push('<hr />');
      i += 1;
      continue;
    }

    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      const level = Math.min(heading[1].length + 0, 4);
      out.push(`<h${level}>${inline(heading[2])}</h${level}>`);
      i += 1;
      continue;
    }

    if (!line.trim()) {
      i += 1;
      continue;
    }

    const paragraph: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() &&
      !/^(#{1,4}\s|\s*([-*+]|\d+\.)\s|\s*&gt;)/.test(lines[i]) &&
      !lines[i].trim().startsWith('|')
    ) {
      paragraph.push(lines[i++]);
    }
    out.push(`<p>${inline(paragraph.join(' '))}</p>`);
  }

  return out.join('\n');
}

/**
 * Abre una ventana con el informe maquetado y lanza la impresión, donde el
 * navegador ofrece «Guardar como PDF». Devuelve false si el bloqueador de
 * ventanas emergentes lo impidió, para poder avisar en vez de fallar en
 * silencio.
 */
export function printReportAsPdf(text: string, meta: ReportMeta = {}): boolean {
  const win = window.open('', '_blank', 'width=900,height=1000');
  if (!win) return false;

  const title = `ARGOS · Informe · ${stamp()}`;
  const trace = meta.tools?.length
    ? '<h4>Trazabilidad</h4><ul>' +
      meta.tools
        .map((t) => {
          const args = Object.entries(t.args ?? {})
            .map(([k, v]) => `${k}=${String(v)}`)
            .join(', ');
          return `<li><code>${escapeHtml(t.name)}</code>${args ? ` <span>(${escapeHtml(args)})</span>` : ''}</li>`;
        })
        .join('') +
      '</ul>'
    : '';

  win.document.write(`<!doctype html>
<html lang="es"><head><meta charset="utf-8" /><title>${escapeHtml(title)}</title>
<style>
  @page { margin: 18mm 16mm; }
  * { box-sizing: border-box; }
  body { font: 11pt/1.5 "Segoe UI", system-ui, sans-serif; color: #14202b; margin: 0; }
  header { border-bottom: 2px solid #14202b; padding-bottom: 8px; margin-bottom: 18px; }
  header .brand { font-size: 8pt; letter-spacing: .18em; color: #5a7182; text-transform: uppercase; }
  header h1 { font-size: 15pt; margin: 3px 0 0; }
  header .when { font-size: 8.5pt; color: #5a7182; }
  h1, h2, h3, h4 { color: #0f2436; line-height: 1.25; }
  h1 { font-size: 14pt; margin: 18px 0 6px; }
  h2 { font-size: 12.5pt; margin: 16px 0 6px; }
  h3 { font-size: 11pt; margin: 14px 0 5px; }
  h4 { font-size: 10pt; margin: 12px 0 4px; }
  p { margin: 6px 0; }
  ul, ol { margin: 6px 0; padding-left: 20px; }
  li { margin: 2px 0; }
  code { font-family: Consolas, monospace; font-size: 9.5pt; background: #eef3f6; padding: 1px 3px; }
  blockquote { margin: 8px 0; padding: 6px 10px; border-left: 3px solid #9fb4c2; background: #f4f8fa; color: #37505f; }
  hr { border: 0; border-top: 1px solid #d3dee5; margin: 14px 0; }
  table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 9.5pt; }
  th, td { border: 1px solid #c8d6df; padding: 4px 7px; text-align: left; vertical-align: top; }
  th { background: #eef3f6; font-weight: 600; }
  /* Que una tabla no se parta a la mitad entre dos paginas. */
  table, blockquote, pre { break-inside: avoid; }
  h1, h2, h3, h4 { break-after: avoid; }
  footer { margin-top: 22px; padding-top: 10px; border-top: 1px solid #d3dee5;
           font-size: 8.5pt; color: #5a7182; }
  footer p { margin: 2px 0; }
  footer ul { margin: 3px 0; }
  @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
</style></head>
<body>
  <header>
    <div class="brand">ARGOS-SOC IA · Informe del asistente</div>
    <h1>Informe generado desde el panel</h1>
    <div class="when">${escapeHtml(stamp())}</div>
  </header>
  <main>${markdownToHtml(text)}</main>
  <footer>
    ${trace}
    ${footerLines(meta).map((line) => `<p>${escapeHtml(line)}</p>`).join('')}
  </footer>
</body></html>`);
  win.document.close();

  // Sin el retardo, Chrome abre el diálogo antes de aplicar los estilos y el
  // PDF sale sin maquetar.
  win.setTimeout(() => {
    win.focus();
    win.print();
  }, 300);
  return true;
}
