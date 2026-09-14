// Resuelve el alias "@/..." de tsconfig cuando los modulos de lib/ se ejecutan
// con node directamente, fuera del bundler de Next. Asi lib/ conserva la
// convencion del proyecto y el corredor de sombra no necesita dependencias.
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const ROOT = process.env.ARGOS_PROJECT_ROOT ?? process.cwd();

export async function resolve(specifier, context, next) {
  if (specifier.startsWith('@/')) {
    const base = path.join(ROOT, specifier.slice(2));
    for (const candidate of [`${base}.ts`, `${base}.tsx`, `${base}.js`, base]) {
      try {
        return await next(pathToFileURL(candidate).href, context);
      } catch {
        // siguiente extension
      }
    }
  }
  return next(specifier, context);
}
