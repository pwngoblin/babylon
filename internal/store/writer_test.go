package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

func TestWriterBatchesConcurrentWritesAndIsolatesFailures(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(db)
	defer s.Close()
	ctx := context.Background()
	if _, err := db.Exec(`CREATE TABLE kv(k TEXT PRIMARY KEY, v INTEGER)`); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var failed int
	for i := 0; i < 400; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "k" + string(rune('A'+i%50)) + string(rune('a'+i/50)) // unique
			if i%10 == 0 {
				key = "dup" // 40 writers fight over one key: first wins, rest fail alone
			}
			err := s.W.Do(ctx, func(tx *sql.Tx) error {
				_, err := tx.Exec(`INSERT INTO kv VALUES(?,?)`, key, i)
				return err
			})
			if err != nil {
				mu.Lock()
				failed++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	var n int
	db.QueryRow(`SELECT COUNT(*) FROM kv`).Scan(&n)
	// 360 unique + 1 "dup" row; the other 39 dup writers failed without
	// poisoning their batch neighbours.
	if n != 361 || failed != 39 {
		t.Fatalf("rows=%d failed=%d, want 361 and 39", n, failed)
	}
}

func TestWriterPanicAndClose(t *testing.T) {
	db, _ := Open(filepath.Join(t.TempDir(), "w.db"))
	s := New(db)
	if err := s.W.Do(context.Background(), func(*sql.Tx) error { panic("x") }); err == nil {
		t.Fatal("panic must surface as error")
	}
	if err := s.W.Do(context.Background(), func(tx *sql.Tx) error { return nil }); err != nil {
		t.Fatalf("writer must survive a panicking op: %v", err)
	}
	s.W.Close()
	if err := s.W.Do(context.Background(), func(*sql.Tx) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
	db.Close()
}
