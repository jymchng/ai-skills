// Secure look-alike of go/main.go.
package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

var allowedHosts = map[string]bool{"api.partner.example": true}

func listOrders(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	// Placeholder query: the term is bound, not formatted into the statement.
	rows, _ := db.Query("SELECT * FROM orders WHERE name = $1", r.URL.Query().Get("term"))
	defer rows.Close()
}

func report(w http.ResponseWriter, r *http.Request) {
	// Fixed argv, no shell.
	out, _ := exec.Command("tar", "-czf", "/tmp/report.tar", r.FormValue("name")).Output()
	w.Write(out)
}

func download(w http.ResponseWriter, r *http.Request) {
	// Reduced to a basename inside the data root.
	name := filepath.Base(r.URL.Query().Get("name"))
	data, _ := os.ReadFile(filepath.Join("/srv/data", name))
	w.Write(data)
}

func preview(w http.ResponseWriter, r *http.Request) {
	// Only allow-listed hosts are reached.
	target := r.FormValue("url")
	if !allowedHosts[hostOf(target)] {
		http.Error(w, "blocked", http.StatusBadRequest)
		return
	}
	resp, _ := http.Get(target)
	defer resp.Body.Close()
}

func decode(w http.ResponseWriter, r *http.Request) {
	// Structured JSON, not a native object decoder.
	var state map[string]string
	json.NewDecoder(r.Body).Decode(&state)
}
