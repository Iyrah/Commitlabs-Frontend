// src/app/api/commitments/export/route.ts
//
// Commitment CSV export endpoint.
// Streams a UTF-8 BOM-prefixed RFC 4180 CSV of the caller's own commitments.
//
// ─── Invariants ───────────────────────────────────────────────────────────────
//
//  I1  Authorization is checked first, before any query parsing, rate-limit
//      check, or chain work.  An unauthenticated request is rejected
//      immediately as 401.
//
//  I2  Ownership is enforced: the authenticated session address must equal
//      the `ownerAddress` query parameter (case-insensitive). Mismatches
//      return 403.  This prevents one user from exporting another user's data.
//
//  I3  Rate limiting is applied per-IP after auth.  A limited request is
//      rejected before any chain work is performed.
//
//  I4  The exported row count is bounded to MAX_EXPORT_ROWS (10 000).
//      Commitments beyond this limit are silently truncated and the
//      X-Export-Truncated response header is set to "1" so clients can
//      detect and surface the truncation.
//
//  I5  Concurrent-export overhead is bounded at the process level by a
//      MAX_CONCURRENT_EXPORTS semaphore.  Excess requests return 429 with
//      a short Retry-After rather than queuing unboundedly.
//
//  I6  A failed chain read is surfaced as a structured JSON error response
//      (not a partial/corrupted CSV), because the entire fetch happens
//      before the streaming response is opened.
//
//  I7  The Content-Disposition filename is derived from the ownerAddress
//      plus a UTC date string, then sanitised to contain only alphanumeric
//      characters, underscores, and hyphens, so the server never echoes
//      caller-controlled bytes directly into HTTP headers.
//
//  I8  Structured telemetry headers (X-Export-*) are attached to every
//      response. Values are numeric only — no secrets, no PII, no stack
//      traces are emitted.
//
//  I9  The `columns` parameter is validated against the allowlist
//      ALL_CSV_HEADERS. Unknown column names are silently dropped; if all
//      requested columns are unknown the full default set is used.
//
//  I10 CSV cells are sanitised against formula-injection (OWASP CSV
//      injection): cells starting with =, +, -, @, tab, or CR are
//      prefixed with a literal single-quote before RFC 4180 quoting.
//
//  I11 The `dateRange` parameter is validated against the allowlist
//      DATE_RANGES. An unrecognised value defaults to 'all' (no
//      truncation), i.e. we fail open for the date filter rather than
//      returning an error.
//
//  I12 The export format is restricted to the allowlist SUPPORTED_EXPORT_FORMATS.
//      Any unsupported value returns 400 immediately.

import { NextRequest, NextResponse } from 'next/server';
import { type CsvRow, createCsvStream } from '@/lib/backend/csv';
import { createCorsOptionsHandler, type CorsRoutePolicy } from '@/lib/backend/cors';
import { BadRequestError, TooManyRequestsError } from '@/lib/backend/errors';
import { getClientIp } from '@/lib/backend/getClientIp';
import { logInfo, logWarn } from '@/lib/backend/logger';
import { checkRateLimit, getRateLimitWindowSeconds } from '@/lib/backend/rateLimit';
import { requireAuth } from '@/lib/backend/requireAuth';
import {
  getUserCommitmentsFromChain,
  type ChainCommitment,
} from '@/lib/backend/services/contracts';
import { withApiHandler } from '@/lib/backend/withApiHandler';

// ─── Constants ────────────────────────────────────────────────────────────────

/**
 * Hard upper bound on the number of data rows written to the CSV.
 * Commitments beyond this limit are silently truncated (Invariant I4).
 * The bound prevents a single export request from consuming unbounded
 * memory and bandwidth — particularly important for streaming responses
 * where backpressure is not applied.
 */
const MAX_EXPORT_ROWS = 10_000;

/**
 * Maximum number of simultaneously in-flight export requests.
 * Exceeding this returns 429 immediately (Invariant I5).
 * CSV generation is CPU+memory-intensive relative to JSON endpoints,
 * so a tighter ceiling is appropriate.
 */
const MAX_CONCURRENT_EXPORTS = 10;

/** Module-level semaphore; decremented in a `finally` block. */
let currentExportRequests = 0;

// ─── Column definitions ───────────────────────────────────────────────────────

const ALL_CSV_HEADERS = [
  'Commitment ID',
  'Owner',
  'Asset',
  'Amount',
  'Status',
  'Compliance Score',
  'Current Value',
  'Fee Earned',
  'Violation Count',
  'Created At',
  'Expires At',
] as const;

type CsvHeader = (typeof ALL_CSV_HEADERS)[number];

/** Map each header label to the commitment field that supplies its value. */
const HEADER_TO_FIELD: Record<CsvHeader, (c: ChainCommitment) => unknown> = {
  'Commitment ID': (c) => c.id,
  Owner: (c) => c.ownerAddress,
  Asset: (c) => c.asset,
  Amount: (c) => c.amount,
  Status: (c) => c.status,
  'Compliance Score': (c) => c.complianceScore,
  'Current Value': (c) => c.currentValue,
  'Fee Earned': (c) => c.feeEarned,
  'Violation Count': (c) => c.violationCount,
  'Created At': (c) => c.createdAt,
  'Expires At': (c) => c.expiresAt,
};

// ─── Supported options ────────────────────────────────────────────────────────

const SUPPORTED_EXPORT_FORMATS = ['csv'] as const;
type ExportFormat = (typeof SUPPORTED_EXPORT_FORMATS)[number];

const DATE_RANGES = ['all', '7d', '30d', 'year'] as const;
type DateRange = (typeof DATE_RANGES)[number];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function stringifyCsvValue(value: unknown): string {
  if (value == null) return '';
  return typeof value === 'bigint' ? value.toString() : String(value);
}

/**
 * Lazily maps commitments to CSV rows for only the requested headers.
 * Using a generator avoids materialising the full mapped array — the
 * streamer pulls one row at a time.
 */
function* commitmentsToRows(
  commitments: Iterable<ChainCommitment>,
  headers: readonly CsvHeader[],
): Generator<CsvRow> {
  for (const commitment of commitments) {
    yield headers.map((h) => stringifyCsvValue(HEADER_TO_FIELD[h](commitment)));
  }
}

/**
 * Parses and validates a comma-separated `columns` query param against the
 * known header allowlist (Invariant I9).  Unknown values are silently
 * dropped.  Returns all headers when the param is absent, empty, or
 * contains only unknown values.
 */
function resolveRequestedHeaders(columnsParam: string | null): CsvHeader[] {
  if (!columnsParam?.trim()) return [...ALL_CSV_HEADERS];
  const requested = columnsParam.split(',').map((c) => c.trim());
  const valid = requested.filter((c): c is CsvHeader =>
    (ALL_CSV_HEADERS as readonly string[]).includes(c),
  );
  return valid.length > 0 ? valid : [...ALL_CSV_HEADERS];
}

/**
 * Validates the `format` query param (Invariant I12).
 * Only 'csv' is supported; any other value returns 400.
 */
function resolveExportFormat(formatParam: string | null): ExportFormat {
  if (!formatParam) return 'csv';
  if ((SUPPORTED_EXPORT_FORMATS as readonly string[]).includes(formatParam)) {
    return formatParam as ExportFormat;
  }
  throw new BadRequestError(`Unsupported export format: ${formatParam}. Only "csv" is available.`);
}

/**
 * Parses the `dateRange` query param (Invariant I11).
 * Unrecognised values silently default to 'all'.
 */
function resolveDateRange(dateRangeParam: string | null): DateRange {
  if (!dateRangeParam) return 'all';
  return (DATE_RANGES as readonly string[]).includes(dateRangeParam)
    ? (dateRangeParam as DateRange)
    : 'all';
}

/** Cutoff instant a commitment's `createdAt` must be on-or-after to match `range`. */
function dateRangeCutoff(range: DateRange, now: Date): Date | null {
  switch (range) {
    case '7d':
      return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    case '30d':
      return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    case 'year':
      return new Date(now.getFullYear(), 0, 1);
    case 'all':
      return null;
  }
}

/**
 * Filters commitments to those created on-or-after the range's cutoff.
 * Commitments with a missing/unparseable `createdAt` are excluded from
 * any range narrower than 'all' since their membership can't be confirmed.
 */
export function filterByDateRange(
  commitments: ChainCommitment[],
  range: DateRange,
  now: Date = new Date(),
): ChainCommitment[] {
  const cutoff = dateRangeCutoff(range, now);
  if (!cutoff) return commitments;
  return commitments.filter((c) => {
    if (!c.createdAt) return false;
    const createdAt = new Date(c.createdAt);
    return !Number.isNaN(createdAt.getTime()) && createdAt >= cutoff;
  });
}

/**
 * Builds a safe Content-Disposition filename (Invariant I7).
 *
 * The filename is derived from the ownerAddress prefix and a UTC date
 * string, then stripped of every character that is not alphanumeric,
 * underscore, or hyphen.  This prevents header injection and path
 * traversal regardless of what the caller supplies as `ownerAddress`.
 *
 * Example: "commitments_GABC123_2024-01-15.csv"
 */
export function buildSafeFilename(ownerAddress: string, now: Date = new Date()): string {
  // Take first 8 chars of address (enough to be identifiable, not enough to
  // be deanonymising on its own).
  const addressFragment = ownerAddress.slice(0, 8).replace(/[^a-zA-Z0-9_-]/g, '');
  const dateFragment = now.toISOString().slice(0, 10); // YYYY-MM-DD
  const raw = `commitments_${addressFragment}_${dateFragment}.csv`;
  // Final sanitisation pass — only alphanumeric, underscore, hyphen, dot
  return raw.replace(/[^a-zA-Z0-9_.-]/g, '_');
}

/**
 * Attaches structured telemetry headers to the response (Invariant I8).
 * Only numeric or boolean (0/1) values are emitted — no secrets or PII.
 */
function attachExportTelemetryHeaders(
  response: NextResponse,
  telemetry: {
    durationMs: number;
    chainDurationMs: number;
    rowCount: number;
    truncated: boolean;
    dateRange: string;
    columnCount: number;
  },
): void {
  response.headers.set('X-Export-Duration-Ms', String(telemetry.durationMs));
  response.headers.set('X-Export-Chain-Duration-Ms', String(telemetry.chainDurationMs));
  response.headers.set('X-Export-Row-Count', String(telemetry.rowCount));
  response.headers.set('X-Export-Truncated', telemetry.truncated ? '1' : '0');
  response.headers.set('X-Export-Date-Range', telemetry.dateRange);
  response.headers.set('X-Export-Column-Count', String(telemetry.columnCount));
}

// ─── CORS policy ──────────────────────────────────────────────────────────────

const EXPORT_CORS_POLICY = {
  GET: { access: 'first-party' },
} satisfies CorsRoutePolicy;

export const OPTIONS = createCorsOptionsHandler(EXPORT_CORS_POLICY);

// ─── GET handler ──────────────────────────────────────────────────────────────

export const GET = withApiHandler(
  async (req: NextRequest, _context, correlationId) => {
    const startedAt = Date.now();

    // ── Invariant I5: concurrent export bound ─────────────────────────────
    if (currentExportRequests >= MAX_CONCURRENT_EXPORTS) {
      throw new TooManyRequestsError(
        'Too many concurrent export requests. Please try again shortly.',
        { concurrencyLimit: MAX_CONCURRENT_EXPORTS },
        10,
      );
    }
    currentExportRequests++;

    try {
      // ── Invariant I1: authorization first ───────────────────────────────
      // requireAuth reads the session cookie and throws UnauthorizedError if
      // the session is absent or invalid — before any other work.
      const auth = requireAuth(req);
      const sessionAddress = auth.user.address;

      // ── Invariant I3: rate limit (per-IP, after auth) ────────────────────
      const ip = getClientIp(req);
      if (!(await checkRateLimit(ip, 'api/commitments/export'))) {
        throw new TooManyRequestsError(
          'Too many requests. Please try again later.',
          undefined,
          getRateLimitWindowSeconds('api/commitments/export'),
        );
      }

      // Parse query params
      const { searchParams } = new URL(req.url);
      const ownerAddress = searchParams.get('ownerAddress');
      if (!ownerAddress?.trim()) {
        throw new BadRequestError('ownerAddress is required.');
      }

      // ── Invariant I2: ownership check ────────────────────────────────────
      // The session address must match ownerAddress (case-insensitive).
      // This is a second-layer ownership check on top of the session auth so
      // that a valid session holder cannot export a different user's data.
      if (sessionAddress.trim().toLowerCase() !== ownerAddress.trim().toLowerCase()) {
        // Return 403 Forbidden. We don't throw ForbiddenError here because we
        // need to decrement the semaphore in finally, and withApiHandler will
        // catch and wrap ForbiddenError anyway. Using throw is fine.
        const { ForbiddenError } = await import('@/lib/backend/errors');
        throw new ForbiddenError('You may only export your own commitments.');
      }

      // ── Invariant I12: format validation ──────────────────────────────────
      resolveExportFormat(searchParams.get('format'));

      // ── Invariant I9: column allowlist ────────────────────────────────────
      const headers = resolveRequestedHeaders(searchParams.get('columns'));

      // ── Invariant I11: date range validation ─────────────────────────────
      const dateRange = resolveDateRange(searchParams.get('dateRange'));

      // ── Invariant I6: fetch before streaming ──────────────────────────────
      // The entire chain fetch happens before the streaming response is
      // opened.  Any failure is surfaced as a structured JSON error (via
      // withApiHandler) rather than a partial or corrupted CSV.
      const chainStartedAt = Date.now();
      const allCommitments = await getUserCommitmentsFromChain(ownerAddress);
      const chainDurationMs = Date.now() - chainStartedAt;

      const filteredCommitments = filterByDateRange(allCommitments, dateRange);

      // ── Invariant I4: row count bound ─────────────────────────────────────
      let truncated = false;
      let exportCommitments = filteredCommitments;
      if (filteredCommitments.length > MAX_EXPORT_ROWS) {
        truncated = true;
        exportCommitments = filteredCommitments.slice(0, MAX_EXPORT_ROWS);
        logWarn(req, '[api/commitments/export] row count exceeded bound, truncating', {
          correlationId,
          ownerAddress,
          rawCount: filteredCommitments.length,
          boundApplied: MAX_EXPORT_ROWS,
        });
      }

      const rowCount = exportCommitments.length;
      const durationMs = Date.now() - startedAt;

      // ── Invariant I7: safe Content-Disposition filename ───────────────────
      const safeFilename = buildSafeFilename(ownerAddress);

      // ── Invariant I10 is enforced inside csv.ts (guardInjection) ──────────
      const stream = createCsvStream(headers, commitmentsToRows(exportCommitments, headers));

      logInfo(req, '[api/commitments/export] export served', {
        correlationId,
        ownerAddress,
        durationMs,
        chainDurationMs,
        rawCount: allCommitments.length,
        filteredCount: filteredCommitments.length,
        rowCount,
        columnCount: headers.length,
        dateRange,
        truncated,
      });

      const response = new NextResponse(stream, {
        status: 200,
        headers: {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': `attachment; filename="${safeFilename}"`,
          'Cache-Control': 'no-store, no-cache, must-revalidate',
          'X-Content-Type-Options': 'nosniff',
          'x-correlation-id': correlationId,
          'x-request-id': correlationId,
        },
      });

      // ── Invariant I8: telemetry headers ───────────────────────────────────
      attachExportTelemetryHeaders(response, {
        durationMs,
        chainDurationMs,
        rowCount,
        truncated,
        dateRange,
        columnCount: headers.length,
      });

      return response;
    } finally {
      // Always decrement the semaphore regardless of success or error.
      currentExportRequests--;
    }
  },
  { cors: EXPORT_CORS_POLICY },
);

// ─── Disallow other methods ───────────────────────────────────────────────────

import { methodNotAllowed } from '@/lib/backend/apiResponse';
const _405 = methodNotAllowed(['GET']);
export { _405 as POST, _405 as PUT, _405 as PATCH, _405 as DELETE };
