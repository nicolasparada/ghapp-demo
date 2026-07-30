package postgres

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nicolasparada/ghapp-demo/server/db/migrations"
)

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied := map[string]struct{}{}
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("load applied migrations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return fmt.Errorf("scan migration version: %w", err)
		}
		applied[version] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate applied migrations: %w", err)
	}

	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".sql" {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)

	for _, name := range files {
		if _, ok := applied[name]; ok {
			continue
		}

		content, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		if err := applyMigration(ctx, pool, name, string(content)); err != nil {
			return err
		}
	}

	return nil
}

func applyMigration(ctx context.Context, pool *pgxpool.Pool, name string, sql string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration transaction (%s): %w", name, err)
	}
	defer tx.Rollback(ctx)

	for _, stmt := range splitStatements(sql) {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}

	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ($1)`, name); err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %s: %w", name, err)
	}

	return nil
}

func splitStatements(sql string) []string {
	stmts := make([]string, 0, 8)
	var current strings.Builder

	inLineComment := false
	inSingleQuote := false
	inDoubleQuote := false
	dollarTag := ""

	for i := 0; i < len(sql); i++ {
		ch := sql[i]

		if inLineComment {
			if ch == '\n' {
				inLineComment = false
				current.WriteByte(ch)
			}
			continue
		}

		if dollarTag != "" {
			if strings.HasPrefix(sql[i:], dollarTag) {
				current.WriteString(dollarTag)
				i += len(dollarTag) - 1
				dollarTag = ""
				continue
			}
			current.WriteByte(ch)
			continue
		}

		if inSingleQuote {
			current.WriteByte(ch)
			if ch == '\'' {
				if i+1 < len(sql) && sql[i+1] == '\'' {
					current.WriteByte(sql[i+1])
					i++
					continue
				}
				inSingleQuote = false
			}
			continue
		}

		if inDoubleQuote {
			current.WriteByte(ch)
			if ch == '"' {
				if i+1 < len(sql) && sql[i+1] == '"' {
					current.WriteByte(sql[i+1])
					i++
					continue
				}
				inDoubleQuote = false
			}
			continue
		}

		if ch == '-' && i+1 < len(sql) && sql[i+1] == '-' {
			inLineComment = true
			i++
			continue
		}

		if ch == '\'' {
			inSingleQuote = true
			current.WriteByte(ch)
			continue
		}

		if ch == '"' {
			inDoubleQuote = true
			current.WriteByte(ch)
			continue
		}

		if ch == '$' {
			tag, ok := parseDollarTag(sql, i)
			if ok {
				dollarTag = tag
				current.WriteString(tag)
				i += len(tag) - 1
				continue
			}
		}

		if ch == ';' {
			stmt := strings.TrimSpace(current.String())
			if stmt != "" {
				stmts = append(stmts, stmt)
			}
			current.Reset()
			continue
		}

		current.WriteByte(ch)
	}

	stmt := strings.TrimSpace(current.String())
	if stmt != "" {
		stmts = append(stmts, stmt)
	}

	return stmts
}

func parseDollarTag(s string, start int) (string, bool) {
	if start >= len(s) || s[start] != '$' {
		return "", false
	}
	for i := start + 1; i < len(s); i++ {
		ch := s[i]
		if ch == '$' {
			return s[start : i+1], true
		}
		if !(ch == '_' || (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
			return "", false
		}
	}
	return "", false
}
