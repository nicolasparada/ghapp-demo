package postgres

import (
	"reflect"
	"testing"
)

func TestSplitStatements(t *testing.T) {
	input := `
-- leading comment should be ignored
CREATE TABLE IF NOT EXISTS test_table (id BIGSERIAL PRIMARY KEY);

DO $$
BEGIN
    RAISE NOTICE 'semicolon ; inside string';
END $$;

INSERT INTO test_table DEFAULT VALUES;
`

	got := splitStatements(input)
	want := []string{
		"CREATE TABLE IF NOT EXISTS test_table (id BIGSERIAL PRIMARY KEY)",
		"DO $$\nBEGIN\n    RAISE NOTICE 'semicolon ; inside string';\nEND $$",
		"INSERT INTO test_table DEFAULT VALUES",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected statements\n got: %#v\nwant: %#v", got, want)
	}
}

func TestSplitStatements_DollarTaggedBlock(t *testing.T) {
	input := `
DO $func$
BEGIN
    PERFORM 1;
END
$func$;

SELECT 1;
`

	got := splitStatements(input)
	want := []string{
		"DO $func$\nBEGIN\n    PERFORM 1;\nEND\n$func$",
		"SELECT 1",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected statements\n got: %#v\nwant: %#v", got, want)
	}
}
