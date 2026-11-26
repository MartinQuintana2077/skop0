// Cache en memoria para traducciones rápidas instantáneas
const translationCache = new Map();

/**
 * Traduce una cadena de texto al español utilizando el servicio libre de Google Translate
 * y almacena el resultado en memoria para no repetir peticiones.
 */
export async function translateToSpanish(text) {
  if (!text || text === 'Sin descripción' || text === 'Sin descripción disponible.' || text.length < 5) {
    return text;
  }
  
  if (translationCache.has(text)) {
    return translationCache.get(text);
  }

  try {
    const url = 'https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=es&dt=t&q=' + encodeURIComponent(text);
    const res = await fetch(url);
    if (res.ok) {
      const data = await res.json();
      if (data && data[0]) {
        const translated = data[0].map(part => part[0]).filter(Boolean).join('');
        if (translated && translated.trim().length > 0) {
          translationCache.set(text, translated.trim());
          return translated.trim();
        }
      }
    }
  } catch (err) {
    console.warn('[Translator] No se pudo traducir online:', err);
  }
  
  return text;
}
