package demo

// The demo target is a small Go notes API with two real defects (an IDOR in
// Get and a path traversal in Export) and one decoy (Search looks injectable
// but uses placeholders). It is kept as string constants, not as .go files,
// so the vulnerable code is never compiled, vetted, or scanned as part of
// this module.

const fixtureGoMod = `module example.com/notes-api

go 1.24
`

const fixtureMain = `package main

import (
	"database/sql"
	"log"
	"net/http"

	"example.com/notes-api/internal/notes"
)

func main() {
	db, err := sql.Open("sqlite", "notes.db")
	if err != nil {
		log.Fatal(err)
	}
	h := &notes.Handler{DB: db, ExportDir: "/var/lib/notes/exports"}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /notes/{id}", h.Get)
	mux.HandleFunc("GET /search", h.Search)
	mux.HandleFunc("GET /export", h.Export)
	log.Fatal(http.ListenAndServe(":8080", mux))
}
`

const fixtureSession = `package auth

import "net/http"

var sessions = map[string]string{}

// CurrentUser returns the user bound to the session cookie, or "".
func CurrentUser(r *http.Request) string {
	c, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return sessions[c.Value]
}
`

const fixtureHandler = `package notes

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"example.com/notes-api/internal/auth"
)

type Handler struct {
	DB        *sql.DB
	ExportDir string
}

// Get returns one note by id.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(r)
	if user == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	row := h.DB.QueryRow("SELECT owner, body FROM notes WHERE id = ?", id)
	var owner, body string
	if err := row.Scan(&owner, &body); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"id": id, "body": body})
}

// Search finds the caller's notes that contain a term.
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(r)
	term := r.URL.Query().Get("q")
	pattern := "%" + term + "%"
	rows, err := h.DB.Query("SELECT id FROM notes WHERE owner = ? AND body LIKE ?", user, pattern)
	if err != nil {
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	json.NewEncoder(w).Encode(ids)
}

// Export streams a previously generated export file.
func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(r) == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := r.URL.Query().Get("name")
	data, err := os.ReadFile(filepath.Join(h.ExportDir, name))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Write(data)
}
`

// fixtureFiles maps repository-relative paths to file contents.
var fixtureFiles = map[string]string{
	"go.mod":                    fixtureGoMod,
	"cmd/server/main.go":        fixtureMain,
	"internal/auth/session.go":  fixtureSession,
	"internal/notes/handler.go": fixtureHandler,
}

const fixtureArchitecture = `# notes-api architecture

notes-api is a single Go HTTP service (cmd/server/main.go) that exposes three
authenticated read endpoints over a SQL database and an export directory.

## Trust boundaries

- Network to handler: every request arrives from an untrusted client. The only
  identity signal is the "session" cookie, resolved by auth.CurrentUser
  (internal/auth/session.go).
- Handler to database: notes rows carry an owner column. Handlers are expected
  to bind every read to the caller's identity.
- Handler to filesystem: Export reads files below ExportDir
  (/var/lib/notes/exports). Request input must never select a path outside it.

## Entrypoints

- GET /notes/{id} -> notes.Handler.Get
- GET /search?q= -> notes.Handler.Search
- GET /export?name= -> notes.Handler.Export

## Privileged sinks

- DB.QueryRow and DB.Query in internal/notes/handler.go
- os.ReadFile in internal/notes/handler.go
`
