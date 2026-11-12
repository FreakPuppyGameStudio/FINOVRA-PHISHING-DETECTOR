#!/usr/bin/env bash
#
# Importa listas de dominios maliciosos a la lista local de Finovra Phishing Detector.
#
# Uso:
#   import_blocklist.sh [-o destino] archivo [archivo ...]
#
# Acepta listas en estos formatos (se pueden mezclar):
#   - formato hosts:      "0.0.0.0 dominio.malo"  o  "127.0.0.1 dominio.malo"
#   - lista de URLs:      "https://dominio.malo/ruta"
#   - dominios sueltos:   "dominio.malo"
# Las líneas que empiezan con '#' se ignoran.
#
# Antes de guardar:
#   - quita dominios importantes que nunca deben bloquearse (ver PROTECTED_DOMAINS)
#   - descarta lo que no parezca un dominio válido
#   - elimina duplicados y fusiona con la lista que ya exista
#
# Las listas son de terceros: revisa la licencia y los términos de cada fuente antes de usarla.

set -eu

PROTECTED_DOMAINS="
google.com
gmail.com
youtube.com
microsoft.com
live.com
outlook.com
apple.com
icloud.com
amazon.com
mercadolibre.com.mx
mercadolibre.com
paypal.com
facebook.com
instagram.com
whatsapp.com
netflix.com
github.com
wikipedia.org
bbva.com
bbva.mx
santander.com.mx
banorte.com
bancomer.com.mx
"

DEST="${HOME}/.local/share/finovra-phishing/blocklist.txt"

usage() {
    echo "Uso: $0 [-o destino] archivo [archivo ...]" >&2
    exit 2
}

while getopts "o:h" opt; do
    case "$opt" in
        o) DEST="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

[ "$#" -ge 1 ] || usage

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

NEW="$WORK/new.txt"
PROTECTED="$WORK/protected.txt"
MERGED="$WORK/merged.txt"

printf '%s\n' "$PROTECTED_DOMAINS" | sed '/^$/d' > "$PROTECTED"

: > "$NEW"
for file in "$@"; do
    if [ ! -r "$file" ]; then
        echo "No se puede leer: $file" >&2
        exit 1
    fi
    # Último campo de la línea (formato hosts), sin esquema, sin ruta ni puerto, en minúsculas
    sed -e 's/\r$//' -e 's/#.*$//' "$file" |
        awk '{ if (NF == 0) next; x = $NF;
               sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", x);
               sub(/[\/:?].*$/, "", x);
               print tolower(x) }' >> "$NEW"
done

# Solo dominios con forma válida: etiquetas separadas por puntos, al menos un punto
VALID_RE='^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
TOTAL_READ="$(wc -l < "$NEW" | tr -d ' ')"
grep -E "$VALID_RE" "$NEW" | sort -u > "$WORK/valid.txt" || true
VALID_COUNT="$(wc -l < "$WORK/valid.txt" | tr -d ' ')"

# Quita los dominios protegidos (coincidencia exacta)
grep -v -x -F -f "$PROTECTED" "$WORK/valid.txt" > "$WORK/clean.txt" || true
CLEAN_COUNT="$(wc -l < "$WORK/clean.txt" | tr -d ' ')"
PROTECTED_SKIPPED=$((VALID_COUNT - CLEAN_COUNT))

# Fusiona con la lista existente (sus comentarios y líneas válidas se conservan)
mkdir -p "$(dirname "$DEST")"
{
    if [ -f "$DEST" ]; then
        grep -v '^#' "$DEST" | sed -e 's/#.*$//' | awk 'NF { print tolower($1) }'
    fi
    cat "$WORK/clean.txt"
} | grep -E "$VALID_RE" | sort -u > "$MERGED"
FINAL_COUNT="$(wc -l < "$MERGED" | tr -d ' ')"

{
    echo "# Lista local de dominios maliciosos de Finovra Phishing Detector"
    echo "# Actualizada el $(date +%Y-%m-%d) con $# archivo(s) importado(s)."
    echo "# Un dominio por línea. Las líneas con # son comentarios."
    cat "$MERGED"
} > "$WORK/out.txt"
mv "$WORK/out.txt" "$DEST"

echo "Líneas leídas:           $TOTAL_READ"
echo "Dominios válidos:        $VALID_COUNT"
echo "Protegidos (omitidos):   $PROTECTED_SKIPPED"
echo "Total en la lista:       $FINAL_COUNT"
echo "Guardada en:             $DEST"
