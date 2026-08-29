/**
 * src/lib/backend/csv.ts
 *
 * Minimal, dependency-free CSV streaming utility for export endpoints.
 *
 * Design goals:
 *   - Zero runtime dependencies beyond the Web Streams API (available in
 *     Node 18+ and all modern edge runtimes).
 *   - Memory-constant: rows are pulled lazily from the generator one at a
 *     time; the full result set is never materialised in a single buffer.
 *   - RFC 4180 compliant: fields are quoted when they contain commas,
 *     double-quotes, newlines, or leading/trailing whitespace.
 *   - Safe against CSV injection: fields that begin with =, +, -, @, tab,
 *     or carriage-return (formula-injection vectors in spreadsheet apps) are
 *     prefixed with a single quote so they are treated as text rather than
 *     evaluated as a formula.
 */

// ─── Types ────────────────────────────────────────────────────────────────────

/** A single CSV row: an ordered array of cell values (already stringified). */
export type CsvRow = string[];

// ─── CSV-injection guard ──────────────────────────────────────────────────────

/**
 * Characters that trigger formula execution in common spreadsheet
 * applications (Excel, LibreOffice Calc, Google Sheets).  A field that
 * begins with one of these characters is prefixed with a literal single
 * quote to neutralise it — consistent with OWASP's recommended mitigation.
 *
 * @see https://owasp.org/www-community/attacks/CSV_Injection
 */
const FORMULA_TRIGGER_CHARS = new Set(['=', '+', '-', '@', '\t', '\r']);

function guardInjection(value: string): string {
  if (value.length > 0 && FORMULA_TRIGGER_CHARS.has(value[0]!)) {
    return `'${value}`;
  }
  return value;
}

// ─── RFC 4180 quoting ─────────────────────────────────────────────────────────

/**
 * Wraps a field in double-quotes and escapes any existing double-quotes per
 * RFC 4180 §2.7.  Also applied when the field contains commas, newlines, or
 * leading/trailing whitespace (§2.4, §2.6).
 */
function quoteField(raw: string): string {
  // Apply injection guard before quoting so the prefix is inside the quotes.
  const safe = guardInjection(raw);

  if (
    safe.includes('"') ||
    safe.includes(',') ||
    safe.includes('\n') ||
    safe.includes('\r') ||
    safe !== safe.trim()
  ) {
    return `"${safe.replace(/"/g, '""')}"`;
  }
  return safe;
}

/**
 * Serialises one row into a CRLF-terminated CSV line (RFC 4180 §2.4).
 */
function rowToLine(row: CsvRow): string {
  return row.map(quoteField).join(',') + '\r\n';
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Creates a `ReadableStream<Uint8Array>` that emits a BOM-prefixed UTF-8
 * CSV.
 *
 * The BOM (U+FEFF, `0xEF 0xBB 0xBF` in UTF-8) is prepended so that Excel
 * and Numbers correctly detect UTF-8 encoding when the file is opened
 * directly from the download folder without going through a text-encoding
 * dialog.
 *
 * @param headers  Column header labels (emitted as the first row).
 * @param rows     Lazy generator of data rows.  Each row must have the same
 *                 number of elements as `headers`; missing trailing cells are
 *                 treated as empty strings.
 *
 * @example
 * ```ts
 * const stream = createCsvStream(
 *   ['ID', 'Name'],
 *   (function* () {
 *     yield ['cm_1', 'Alice'];
 *     yield ['cm_2', 'Bob'];
 *   })(),
 * );
 * return new NextResponse(stream, { headers: { 'Content-Type': 'text/csv' } });
 * ```
 */
export function createCsvStream(
  headers: readonly string[],
  rows: Iterable<CsvRow>,
): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  // UTF-8 BOM — signals UTF-8 to Excel/Numbers when opening directly.
  const BOM = new Uint8Array([0xef, 0xbb, 0xbf]);

  return new ReadableStream<Uint8Array>({
    start(controller) {
      // Emit BOM first
      controller.enqueue(BOM);
      // Emit header row
      controller.enqueue(encoder.encode(rowToLine(headers as string[])));

      for (const row of rows) {
        controller.enqueue(encoder.encode(rowToLine(row)));
      }

      controller.close();
    },
  });
}
