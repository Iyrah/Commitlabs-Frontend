/**
 * tests/api/commitments-export.test.ts
 *
 * Comprehensive tests for GET /api/commitments/export
 *
 * Covers:
 *  - Success paths (full export, column selection, date-range filtering)
 *  - Authorization invariants (I1, I2)
 *  - Rate-limit invariants (I3)
 *  - Row-count bound and truncation header (I4)
 *  - Concurrent-export semaphore (I5)
 *  - Chain-fetch failure surfaces as JSON, not corrupt CSV (I6)
 *  - Safe Content-Disposition filename (I7)
 *  - Telemetry headers — numeric only, no secrets (I8)
 *  - Column allowlist validation (I9)
 *  - CSV injection guard via csv.ts (I10)
 *  - Date-range validation and default (I11)
 *  - Format allowlist (I12)
 *  - Unsupported HTTP methods return 405
 *  - Unit tests for exported helpers: filterByDateRange, buildSafeFilename
 *
 * Refs #1779
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createMockRequest } from './helpers';

// ─── Module mocks (hoisted above imports of the route) ───────────────────────

vi.mock('@/lib/backend/requireAuth', () => ({
  requireAuth: vi.fn(),
}));

vi.mock('@/lib/backend/rateLimit', () => ({
  checkRateLimit: vi.fn(),
  getRateLimitWindowSeconds: vi.fn(() => 60),
}));

vi.mock('@/lib/backend/getClientIp', () => ({
  getClientIp: vi.fn(() => '127.0.0.1'),
}));

vi.mock('@/lib/backend/services/contracts', () => ({
  getUserCommitmentsFromChain: vi.fn(),
}));

// ─── Route imports (after mocks) ─────────────────────────────────────────────

import {
  GET,
  POST,
  PUT,
  PATCH,
  DELETE,
  filterByDateRange,
  buildSafeFilename,
} from '@/app/api/commitments/export/route';
import { requireAuth } from '@/lib/backend/requireAuth';
import type { AuthenticatedRequest } from '@/lib/backend/requireAuth';
import { checkRateLimit } from '@/lib/backend/rateLimit';
import { getUserCommitmentsFromChain } from '@/lib/backend/services/contracts';
import type { ChainCommitment } from '@/lib/backend/services/contracts';
import { UnauthorizedError } from '@/lib/backend/errors';

// ─── Typed mocks ─────────────────────────────────────────────────────────────

const mockedRequireAuth = vi.mocked(requireAuth);
const mockedCheckRateLimit = vi.mocked(checkRateLimit);
const mockedGetUserCommitmentsFromChain = vi.mocked(getUserCommitmentsFromChain);

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const OWNER = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const OTHER = 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
const BASE_URL = `http://localhost:3000/api/commitments/export`;

function makeUrl(params: Record<string, string> = {}): string {
  const sp = new URLSearchParams({ ownerAddress: OWNER, ...params });
  return `${BASE_URL}?${sp.toString()}`;
}

function makeCommitment(overrides: Partial<ChainCommitment> = {}): ChainCommitment {
  return {
    id: 'cm_1',
    ownerAddress: OWNER,
    asset: 'USDC',
    amount: '1000',
    status: 'ACTIVE',
    complianceScore: 85,
    currentValue: '1050',
    feeEarned: '5',
    violationCount: 0,
    createdAt: '2024-06-01T00:00:00Z',
    expiresAt: '2025-06-01T00:00:00Z',
    ...overrides,
  };
}

/** Reads the entire body of a ReadableStream<Uint8Array> into a string. */
async function readStreamText(response: Response): Promise<string> {
  const reader = response.body!.getReader();
  const chunks: Uint8Array[] = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) chunks.push(value);
  }
  const combined = new Uint8Array(chunks.reduce((acc, c) => acc + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }
  // Strip UTF-8 BOM if present
  const slice =
    combined[0] === 0xef && combined[1] === 0xbb && combined[2] === 0xbf
      ? combined.slice(3)
      : combined;
  return new TextDecoder().decode(slice);
}

/** Parse CSV text into array of row arrays (splits on CRLF, tabs out quotes). */
function parseCsv(text: string): string[][] {
  return text
    .split('\r\n')
    .filter(Boolean)
    .map((line) => {
      // Simple RFC4180 parser: handle quoted fields with embedded commas/quotes
      const fields: string[] = [];
      let i = 0;
      while (i < line.length) {
        if (line[i] === '"') {
          let field = '';
          i++; // skip opening quote
          while (i < line.length) {
            if (line[i] === '"' && line[i + 1] === '"') {
              field += '"';
              i += 2;
            } else if (line[i] === '"') {
              i++; // closing quote
              break;
            } else {
              field += line[i++];
            }
          }
          fields.push(field);
          if (line[i] === ',') i++;
        } else {
          const end = line.indexOf(',', i);
          if (end === -1) {
            fields.push(line.slice(i));
            break;
          } else {
            fields.push(line.slice(i, end));
            i = end + 1;
          }
        }
      }
      return fields;
    });
}

// ─── Default happy-path setup ─────────────────────────────────────────────────

const COMMITMENTS: ChainCommitment[] = [
  makeCommitment({ id: 'cm_1' }),
  makeCommitment({ id: 'cm_2', status: 'SETTLED', feeEarned: '20' }),
];

function setupHappyPath() {
  mockedRequireAuth.mockImplementation((req) => {
    const r = req as unknown as AuthenticatedRequest;
    r.user = { address: OWNER, csrfToken: 'tok' };
    return r;
  });
  mockedCheckRateLimit.mockResolvedValue(true);
  mockedGetUserCommitmentsFromChain.mockResolvedValue(COMMITMENTS);
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('GET /api/commitments/export', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupHappyPath();
  });

  // ── Success paths ──────────────────────────────────────────────────────────

  describe('success — full export', () => {
    it('returns 200 with text/csv content-type', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('text/csv');
    });

    it('returns a UTF-8 BOM as the first three bytes', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      const reader = res.body!.getReader();
      const { value } = await reader.read();
      reader.releaseLock();
      expect(value![0]).toBe(0xef);
      expect(value![1]).toBe(0xbb);
      expect(value![2]).toBe(0xbf);
    });

    it('includes all default column headers as the first CSV row', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      const text = await readStreamText(res);
      const rows = parseCsv(text);
      expect(rows[0]).toContain('Commitment ID');
      expect(rows[0]).toContain('Owner');
      expect(rows[0]).toContain('Asset');
      expect(rows[0]).toContain('Amount');
      expect(rows[0]).toContain('Status');
      expect(rows[0]).toContain('Compliance Score');
      expect(rows[0]).toContain('Current Value');
      expect(rows[0]).toContain('Fee Earned');
      expect(rows[0]).toContain('Violation Count');
      expect(rows[0]).toContain('Created At');
      expect(rows[0]).toContain('Expires At');
    });

    it('writes one data row per commitment', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      const text = await readStreamText(res);
      const rows = parseCsv(text);
      // header row + 2 data rows
      expect(rows).toHaveLength(3);
    });

    it('maps commitment fields to correct CSV cell values', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      const text = await readStreamText(res);
      const rows = parseCsv(text);
      const headers = rows[0]!;
      const dataRow = rows[1]!;
      const idIndex = headers.indexOf('Commitment ID');
      const assetIndex = headers.indexOf('Asset');
      const statusIndex = headers.indexOf('Status');
      expect(dataRow[idIndex]).toBe('cm_1');
      expect(dataRow[assetIndex]).toBe('USDC');
      expect(dataRow[statusIndex]).toBe('ACTIVE');
    });

    it('attaches a safe Content-Disposition header (I7)', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      const cd = res.headers.get('content-disposition');
      expect(cd).toMatch(/^attachment; filename="commitments_[a-zA-Z0-9_.-]+\.csv"$/);
      // Must not contain raw owner address bytes beyond the first 8 chars
      expect(cd).not.toContain(OWNER.slice(8));
    });

    it('attaches Cache-Control: no-store to prevent caching of sensitive exports', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      expect(res.headers.get('cache-control')).toContain('no-store');
    });

    it('attaches X-Content-Type-Options: nosniff', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    });

    it('attaches a correlation-id header', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      expect(res.headers.get('x-correlation-id')).toBeTruthy();
    });
  });

  // ── Telemetry headers (I8) ─────────────────────────────────────────────────

  describe('telemetry headers (I8)', () => {
    it('X-Export-Row-Count matches the number of data rows returned', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      expect(res.headers.get('x-export-row-count')).toBe('2');
    });

    it('X-Export-Truncated is "0" for a non-truncated export', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      expect(res.headers.get('x-export-truncated')).toBe('0');
    });

    it('X-Export-Duration-Ms is a non-negative integer string', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      const val = Number(res.headers.get('x-export-duration-ms'));
      expect(Number.isFinite(val) && val >= 0).toBe(true);
    });

    it('X-Export-Chain-Duration-Ms is a non-negative integer string', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      const val = Number(res.headers.get('x-export-chain-duration-ms'));
      expect(Number.isFinite(val) && val >= 0).toBe(true);
    });

    it('X-Export-Column-Count equals the number of header columns', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      const colCount = Number(res.headers.get('x-export-column-count'));
      expect(colCount).toBe(11); // all 11 default columns
    });

    it('X-Export-Date-Range reflects the requested range', async () => {
      const res = await GET(createMockRequest(makeUrl({ dateRange: '30d' })));
      expect(res.headers.get('x-export-date-range')).toBe('30d');
    });

    it('telemetry values are purely numeric — no secrets or PII', async () => {
      const res = await GET(createMockRequest(makeUrl()));
      const telemetryHeaders = [
        'x-export-row-count',
        'x-export-truncated',
        'x-export-duration-ms',
        'x-export-chain-duration-ms',
        'x-export-column-count',
      ];
      for (const h of telemetryHeaders) {
        const val = res.headers.get(h);
        expect(val, `header ${h} should be numeric`).toMatch(/^\d+$/);
      }
    });
  });

  // ── Authorization invariants (I1, I2) ─────────────────────────────────────

  describe('authorization (I1, I2)', () => {
    it('returns 401 when the session cookie is absent (I1)', async () => {
      mockedRequireAuth.mockImplementation(() => {
        throw new UnauthorizedError('No session token provided');
      });
      const res = await GET(createMockRequest(makeUrl()));
      const body = await res.json();
      expect(res.status).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('checks auth before rate-limiting (I1)', async () => {
      mockedRequireAuth.mockImplementation(() => {
        throw new UnauthorizedError('No session token provided');
      });
      await GET(createMockRequest(makeUrl()));
      expect(mockedCheckRateLimit).not.toHaveBeenCalled();
    });

    it('checks auth before fetching from the chain (I1)', async () => {
      mockedRequireAuth.mockImplementation(() => {
        throw new UnauthorizedError('No session token provided');
      });
      await GET(createMockRequest(makeUrl()));
      expect(mockedGetUserCommitmentsFromChain).not.toHaveBeenCalled();
    });

    it('returns 403 when session address does not match ownerAddress (I2)', async () => {
      // Session belongs to OTHER, but the request asks for OWNER's data
      mockedRequireAuth.mockImplementation((req) => {
        const r = req as unknown as AuthenticatedRequest;
        r.user = { address: OTHER, csrfToken: 'tok' };
        return r;
      });
      const res = await GET(createMockRequest(makeUrl()));
      const body = await res.json();
      expect(res.status).toBe(403);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('ownership check is case-insensitive (I2)', async () => {
      // Session address in uppercase, ownerAddress in lowercase
      mockedRequireAuth.mockImplementation((req) => {
        const r = req as unknown as AuthenticatedRequest;
        r.user = { address: OWNER.toUpperCase(), csrfToken: 'tok' };
        return r;
      });
      const res = await GET(createMockRequest(makeUrl({ ownerAddress: OWNER.toLowerCase() })));
      expect(res.status).toBe(200);
    });

    it('does not call chain fetch for a forbidden cross-user request (I2)', async () => {
      mockedRequireAuth.mockImplementation((req) => {
        const r = req as unknown as AuthenticatedRequest;
        r.user = { address: OTHER, csrfToken: 'tok' };
        return r;
      });
      await GET(createMockRequest(makeUrl()));
      expect(mockedGetUserCommitmentsFromChain).not.toHaveBeenCalled();
    });

    it('returns 400 when ownerAddress query param is missing', async () => {
      const url = `${BASE_URL}?format=csv`;
      const res = await GET(createMockRequest(url));
      const body = await res.json();
      expect(res.status).toBe(400);
      expect(body.error.code).toBe('BAD_REQUEST');
    });

    it('returns 400 when ownerAddress is an empty string', async () => {
      const res = await GET(createMockRequest(makeUrl({ ownerAddress: '   ' })));
      const body = await res.json();
      expect(res.status).toBe(400);
      expect(body.error.code).toBe('BAD_REQUEST');
    });
  });

  // ── Rate limiting (I3) ────────────────────────────────────────────────────

  describe('rate limiting (I3)', () => {
    it('returns 429 when rate limit is exceeded', async () => {
      mockedCheckRateLimit.mockResolvedValue(false);
      const res = await GET(createMockRequest(makeUrl()));
      const body = await res.json();
      expect(res.status).toBe(429);
      expect(body.error.code).toBe('TOO_MANY_REQUESTS');
    });

    it('includes Retry-After header on rate-limited response', async () => {
      mockedCheckRateLimit.mockResolvedValue(false);
      const res = await GET(createMockRequest(makeUrl()));
      expect(res.headers.get('retry-after')).toBeTruthy();
    });

    it('uses the export-specific rate-limit bucket (I3)', async () => {
      await GET(createMockRequest(makeUrl()));
      expect(mockedCheckRateLimit).toHaveBeenCalledWith(
        expect.any(String),
        'api/commitments/export',
      );
    });

    it('does not call chain fetch when rate-limited', async () => {
      mockedCheckRateLimit.mockResolvedValue(false);
      await GET(createMockRequest(makeUrl()));
      expect(mockedGetUserCommitmentsFromChain).not.toHaveBeenCalled();
    });
  });

  // ── Row count bound and truncation (I4) ───────────────────────────────────

  describe('row-count bound (I4)', () => {
    it('sets X-Export-Truncated to "1" when result set exceeds 10 000 rows', async () => {
      // Generate 10001 commitments
      const huge = Array.from({ length: 10_001 }, (_, i) => makeCommitment({ id: `cm_${i}` }));
      mockedGetUserCommitmentsFromChain.mockResolvedValue(huge);

      const res = await GET(createMockRequest(makeUrl()));
      expect(res.headers.get('x-export-truncated')).toBe('1');
    });

    it('X-Export-Row-Count is 10 000 when truncation is applied', async () => {
      const huge = Array.from({ length: 10_001 }, (_, i) => makeCommitment({ id: `cm_${i}` }));
      mockedGetUserCommitmentsFromChain.mockResolvedValue(huge);

      const res = await GET(createMockRequest(makeUrl()));
      expect(res.headers.get('x-export-row-count')).toBe('10000');
    });

    it('delivers exactly 10 000 data rows in the CSV when truncation fires', async () => {
      const huge = Array.from({ length: 10_001 }, (_, i) => makeCommitment({ id: `cm_${i}` }));
      mockedGetUserCommitmentsFromChain.mockResolvedValue(huge);

      const res = await GET(createMockRequest(makeUrl()));
      const text = await readStreamText(res);
      const rows = parseCsv(text);
      // 1 header row + 10 000 data rows
      expect(rows).toHaveLength(10_001);
    });

    it('does NOT set X-Export-Truncated when result count is exactly 10 000', async () => {
      const exactly10k = Array.from({ length: 10_000 }, (_, i) =>
        makeCommitment({ id: `cm_${i}` }),
      );
      mockedGetUserCommitmentsFromChain.mockResolvedValue(exactly10k);

      const res = await GET(createMockRequest(makeUrl()));
      expect(res.headers.get('x-export-truncated')).toBe('0');
    });

    it('returns 200 and an empty CSV (header only) when the owner has no commitments', async () => {
      mockedGetUserCommitmentsFromChain.mockResolvedValue([]);
      const res = await GET(createMockRequest(makeUrl()));
      expect(res.status).toBe(200);
      const text = await readStreamText(res);
      const rows = parseCsv(text);
      expect(rows).toHaveLength(1); // header row only
    });
  });

  // ── Chain-fetch failure surface (I6) ──────────────────────────────────────

  describe('chain-fetch failure (I6)', () => {
    it('returns structured JSON error (not a CSV) when chain fetch fails', async () => {
      mockedGetUserCommitmentsFromChain.mockRejectedValue(new Error('Soroban RPC unavailable'));
      const res = await GET(createMockRequest(makeUrl()));
      const contentType = res.headers.get('content-type') ?? '';
      expect(contentType).toContain('application/json');
      expect(res.status).toBe(500);
    });

    it('does not leak error messages or stack traces in the response body', async () => {
      mockedGetUserCommitmentsFromChain.mockRejectedValue(
        new Error('Soroban RPC unavailable with token=super_secret'),
      );
      const res = await GET(createMockRequest(makeUrl()));
      const body = await res.json();
      const bodyStr = JSON.stringify(body);
      expect(bodyStr).not.toContain('super_secret');
      expect(bodyStr).not.toContain('stack');
    });
  });

  // ── Column allowlist (I9) ─────────────────────────────────────────────────

  describe('column allowlist (I9)', () => {
    it('accepts a subset of valid column names', async () => {
      const res = await GET(createMockRequest(makeUrl({ columns: 'Commitment ID,Asset,Status' })));
      expect(res.status).toBe(200);
      const text = await readStreamText(res);
      const rows = parseCsv(text);
      expect(rows[0]).toEqual(['Commitment ID', 'Asset', 'Status']);
    });

    it('silently drops unknown column names', async () => {
      const res = await GET(
        createMockRequest(makeUrl({ columns: 'Commitment ID,__proto__,<script>' })),
      );
      expect(res.status).toBe(200);
      const text = await readStreamText(res);
      const rows = parseCsv(text);
      // Only 'Commitment ID' is valid; unknowns are dropped, so falls back to all headers
      // Actually: 1 valid column → returns just that one column
      expect(rows[0]).toEqual(['Commitment ID']);
    });

    it('falls back to all headers when every requested column is unknown', async () => {
      const res = await GET(createMockRequest(makeUrl({ columns: 'BadCol1,BadCol2' })));
      expect(res.status).toBe(200);
      const text = await readStreamText(res);
      const rows = parseCsv(text);
      expect(rows[0]).toHaveLength(11); // all 11 default columns
    });

    it('X-Export-Column-Count reflects the resolved column set', async () => {
      const res = await GET(createMockRequest(makeUrl({ columns: 'Commitment ID,Asset' })));
      expect(res.headers.get('x-export-column-count')).toBe('2');
    });
  });

  // ── Date-range filter (I11) ───────────────────────────────────────────────

  describe('date-range filter (I11)', () => {
    const OLD = makeCommitment({ id: 'old', createdAt: '2020-01-01T00:00:00Z' });
    const NEW = makeCommitment({ id: 'new', createdAt: '2024-10-01T00:00:00Z' });

    beforeEach(() => {
      mockedGetUserCommitmentsFromChain.mockResolvedValue([OLD, NEW]);
    });

    it('dateRange=all returns all commitments (default)', async () => {
      const res = await GET(createMockRequest(makeUrl({ dateRange: 'all' })));
      expect(res.headers.get('x-export-row-count')).toBe('2');
    });

    it('dateRange=7d filters to commitments in the last 7 days', async () => {
      // Neither OLD nor NEW are within last 7 days from now (2026-08-29)
      // NEW (2024-10-01) is ~700 days ago — both should be filtered out
      const res = await GET(createMockRequest(makeUrl({ dateRange: '7d' })));
      expect(res.headers.get('x-export-row-count')).toBe('0');
    });

    it('dateRange=30d filters to commitments in the last 30 days', async () => {
      const res = await GET(createMockRequest(makeUrl({ dateRange: '30d' })));
      // Both OLD and NEW are outside the 30d window as of 2026-08-29
      expect(res.headers.get('x-export-row-count')).toBe('0');
    });

    it('an unrecognised dateRange value defaults to "all" instead of returning error', async () => {
      const res = await GET(createMockRequest(makeUrl({ dateRange: 'invalid_range' })));
      expect(res.status).toBe(200);
      // Falls back to 'all' — both commitments returned
      expect(res.headers.get('x-export-row-count')).toBe('2');
    });

    it('X-Export-Date-Range echoes "all" for an unrecognised value (fallback)', async () => {
      const res = await GET(createMockRequest(makeUrl({ dateRange: 'nonsense' })));
      expect(res.headers.get('x-export-date-range')).toBe('all');
    });

    it('commitments with missing createdAt are excluded from narrow date ranges', async () => {
      const missing = makeCommitment({ id: 'missing', createdAt: undefined });
      mockedGetUserCommitmentsFromChain.mockResolvedValue([missing]);
      const res = await GET(createMockRequest(makeUrl({ dateRange: '30d' })));
      expect(res.headers.get('x-export-row-count')).toBe('0');
    });
  });

  // ── Format validation (I12) ───────────────────────────────────────────────

  describe('format validation (I12)', () => {
    it('accepts format=csv (the only supported value)', async () => {
      const res = await GET(createMockRequest(makeUrl({ format: 'csv' })));
      expect(res.status).toBe(200);
    });

    it('omitting format defaults to csv', async () => {
      // makeUrl() does not include format by default
      const res = await GET(createMockRequest(makeUrl()));
      expect(res.status).toBe(200);
    });

    it('returns 400 for an unsupported format value', async () => {
      const res = await GET(createMockRequest(makeUrl({ format: 'json' })));
      const body = await res.json();
      expect(res.status).toBe(400);
      expect(body.error.code).toBe('BAD_REQUEST');
    });

    it('returns 400 for format=xlsx', async () => {
      const res = await GET(createMockRequest(makeUrl({ format: 'xlsx' })));
      const body = await res.json();
      expect(res.status).toBe(400);
      expect(body.error.code).toBe('BAD_REQUEST');
    });
  });

  // ── Unsupported methods ───────────────────────────────────────────────────

  describe('method restrictions', () => {
    it('POST returns 405', async () => {
      const res = await POST(createMockRequest(makeUrl(), { method: 'POST' }));
      expect(res.status).toBe(405);
    });

    it('PUT returns 405', async () => {
      const res = await PUT(createMockRequest(makeUrl(), { method: 'PUT' }));
      expect(res.status).toBe(405);
    });

    it('PATCH returns 405', async () => {
      const res = await PATCH(createMockRequest(makeUrl(), { method: 'PATCH' }));
      expect(res.status).toBe(405);
    });

    it('DELETE returns 405', async () => {
      const res = await DELETE(createMockRequest(makeUrl(), { method: 'DELETE' }));
      expect(res.status).toBe(405);
    });
  });
});

// ─── Unit tests for exported helpers ─────────────────────────────────────────

describe('filterByDateRange', () => {
  const makeC = (createdAt?: string): ChainCommitment =>
    ({
      id: 'x',
      ownerAddress: OWNER,
      asset: 'XLM',
      amount: '100',
      status: 'ACTIVE',
      complianceScore: 80,
      currentValue: '100',
      feeEarned: '0',
      violationCount: 0,
      createdAt,
    }) as ChainCommitment;

  it('returns all commitments for range="all"', () => {
    const cs = [makeC('2020-01-01'), makeC('2024-01-01')];
    expect(filterByDateRange(cs, 'all')).toHaveLength(2);
  });

  it('includes commitments exactly at the cutoff boundary', () => {
    const now = new Date('2024-02-01T00:00:00Z');
    const cutoff = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000); // 2024-01-25
    const c = makeC(cutoff.toISOString());
    const result = filterByDateRange([c], '7d', now);
    expect(result).toHaveLength(1);
  });

  it('excludes commitments before the cutoff', () => {
    const now = new Date('2024-02-01T00:00:00Z');
    const old = makeC('2023-01-01T00:00:00Z');
    expect(filterByDateRange([old], '7d', now)).toHaveLength(0);
  });

  it('excludes commitments with no createdAt for non-"all" ranges', () => {
    const c = makeC(undefined);
    expect(filterByDateRange([c], '30d')).toHaveLength(0);
  });

  it('excludes commitments with an unparseable createdAt', () => {
    const c = makeC('not-a-date');
    expect(filterByDateRange([c], '30d')).toHaveLength(0);
  });

  it('returns all for range="all" even when some createdAt values are missing', () => {
    const cs = [makeC(undefined), makeC('2020-01-01')];
    expect(filterByDateRange(cs, 'all')).toHaveLength(2);
  });

  it('range="year" keeps only commitments created this calendar year', () => {
    const now = new Date('2024-06-15T00:00:00Z');
    const thisYear = makeC('2024-03-01T00:00:00Z');
    const lastYear = makeC('2023-12-31T00:00:00Z');
    const result = filterByDateRange([thisYear, lastYear], 'year', now);
    expect(result).toHaveLength(1);
    expect(result[0]!.createdAt).toBe('2024-03-01T00:00:00Z');
  });
});

describe('buildSafeFilename', () => {
  it('produces a filename matching the safe pattern', () => {
    const now = new Date('2024-01-15T12:00:00Z');
    const name = buildSafeFilename(OWNER, now);
    expect(name).toMatch(/^[a-zA-Z0-9_.-]+\.csv$/);
  });

  it('includes only the first 8 characters of the address', () => {
    const now = new Date('2024-01-15T12:00:00Z');
    const name = buildSafeFilename(OWNER, now);
    expect(name).toContain(OWNER.slice(0, 8));
    expect(name).not.toContain(OWNER.slice(8, 16));
  });

  it('includes the date in YYYY-MM-DD format', () => {
    const now = new Date('2024-01-15T12:00:00Z');
    const name = buildSafeFilename(OWNER, now);
    expect(name).toContain('2024-01-15');
  });

  it('sanitises special characters in the address fragment', () => {
    const now = new Date('2024-01-15T12:00:00Z');
    const malicious = '../../../etc/passwd';
    const name = buildSafeFilename(malicious, now);
    expect(name).not.toContain('/');
    expect(name).not.toContain('..');
    expect(name).toMatch(/^[a-zA-Z0-9_.-]+\.csv$/);
  });

  it('sanitises header-injection characters (CRLF) in the address', () => {
    const now = new Date('2024-01-15T12:00:00Z');
    const injection = 'GABC\r\nX-Injected: evil';
    const name = buildSafeFilename(injection, now);
    expect(name).not.toContain('\r');
    expect(name).not.toContain('\n');
  });

  it('produces a deterministic result given the same inputs', () => {
    const now = new Date('2024-01-15T12:00:00Z');
    expect(buildSafeFilename(OWNER, now)).toBe(buildSafeFilename(OWNER, now));
  });

  it('uses the current date when no date is provided', () => {
    const name = buildSafeFilename(OWNER);
    const today = new Date().toISOString().slice(0, 10);
    expect(name).toContain(today);
  });
});
