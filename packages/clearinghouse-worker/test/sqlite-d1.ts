import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Every migration, in order, as one SQL script. */
export const MIGRATION_SQL = ['0001_init.sql', '0002_accounts.sql', '0003_constraints.sql']
  .map((f) => readFileSync(path.resolve(__dirname, '../migrations', f), 'utf8'))
  .join(String.fromCharCode(10));

const SYNC_RUN = Symbol('sqlite-d1-sync-run');
const READ_QUERY_RE = /^\s*(SELECT|PRAGMA|WITH|EXPLAIN)\b|\bRETURNING\b/i;

/** An in-memory SQLite database behind the D1 interface the Worker uses. */
export function createSqliteD1(migrationSql: string): { d1: D1Database; raw: DatabaseSync } {
  const raw = new DatabaseSync(':memory:');
  raw.exec('PRAGMA foreign_keys = ON;');
  raw.exec(migrationSql);

  const buildStmt = (query: string) => {
    let bound: Array<string | number | bigint | Uint8Array | null> = [];
    const execSync = () => {
      if (READ_QUERY_RE.test(query)) {
        const rows = raw.prepare(query).all(...bound);
        return {
          results: rows,
          success: true,
          meta: {
            duration: 0,
            size_after: 0,
            rows_read: rows.length,
            rows_written: 0,
            last_row_id: 0,
            changed_db: false,
            changes: 0,
          },
        };
      }
      const info = raw.prepare(query).run(...bound);
      return {
        results: [],
        success: true,
        meta: {
          duration: 0,
          size_after: 0,
          rows_read: 0,
          rows_written: Number(info.changes),
          last_row_id: Number(info.lastInsertRowid),
          changed_db: Number(info.changes) > 0,
          changes: Number(info.changes),
        },
      };
    };

    const stmt: D1PreparedStatement & { [SYNC_RUN]?: typeof execSync } = {
      [SYNC_RUN]: execSync,
      bind(...values: unknown[]) {
        bound = values.map((v) =>
          v === undefined ? null : (v as string | number | bigint | Uint8Array | null),
        );
        return stmt;
      },
      async first<T = unknown>(colName?: string): Promise<T | null> {
        const row = raw.prepare(query).get(...bound) as Record<string, unknown> | undefined;
        if (!row) {
          return null;
        }
        if (colName !== undefined) {
          return (row[colName] ?? null) as T | null;
        }
        return row as unknown as T;
      },
      async run<T = Record<string, unknown>>() {
        const info = raw.prepare(query).run(...bound);
        return {
          results: [] as T[],
          success: true,
          meta: {
            duration: 0,
            size_after: 0,
            rows_read: 0,
            rows_written: Number(info.changes),
            last_row_id: Number(info.lastInsertRowid),
            changed_db: Number(info.changes) > 0,
            changes: Number(info.changes),
          },
        };
      },
      async all<T = Record<string, unknown>>() {
        return execSync() as unknown as D1Result<T>;
      },
      raw: (async <T = unknown[]>(options?: { columnNames?: boolean }) => {
        const rows = raw.prepare(query).all(...bound) as Array<Record<string, unknown>>;
        const values = rows.map((r) => Object.values(r)) as T[];
        if (options?.columnNames) {
          const cols = rows[0] ? Object.keys(rows[0]) : [];
          return [cols, ...values] as [string[], ...T[]];
        }
        return values;
      }) as D1PreparedStatement['raw'],
    };
    return stmt;
  };

  const d1 = {
    prepare(query: string) {
      return buildStmt(query);
    },
    async batch<T = unknown>(statements: D1PreparedStatement[]) {
      const results: Array<D1Result<T>> = [];
      raw.exec('BEGIN IMMEDIATE;');
      try {
        for (const s of statements) {
          const syncFn = (s as D1PreparedStatement & { [SYNC_RUN]?: () => D1Result<T> })[SYNC_RUN];
          if (syncFn) {
            results.push(syncFn());
          } else {
            results.push(await s.all<T>());
          }
        }
        raw.exec('COMMIT;');
        return results;
      } catch (err) {
        try {
          raw.exec('ROLLBACK;');
        } catch {
          // ignore if transaction already rolled back
        }
        throw err;
      }
    },
    async exec(query: string) {
      raw.exec(query);
      return { count: 1, duration: 0 };
    },
    withSession() {
      return d1 as unknown as D1DatabaseSession;
    },
    async dump() {
      return new ArrayBuffer(0);
    },
  } as unknown as D1Database;

  return { d1, raw };
}
