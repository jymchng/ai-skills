// Intentionally vulnerable Go handlers for the fixture.
package main

import (
	"database/sql"
	"encoding/gob"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

func listOrders(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	// go-sql-concat: statement built with fmt.Sprintf
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM orders WHERE name = '%s'", r.URL.Query().Get("term")))
	defer rows.Close()
}

func report(w http.ResponseWriter, r *http.Request) {
	// cmd-go-shell: shell invoked with -c
	out, _ := exec.Command("sh", "-c", r.FormValue("cmd")).Output()
	w.Write(out)
}

func download(w http.ResponseWriter, r *http.Request) {
	// path-traversal: request data used to build the path
	data, _ := os.ReadFile("/srv/data/" + r.URL.Query().Get("name"))
	w.Write(data)
}

func preview(w http.ResponseWriter, r *http.Request) {
	// ssrf: outbound request to a request-supplied URL
	resp, _ := http.Get(r.FormValue("url"))
	defer resp.Body.Close()
}

func echo(w http.ResponseWriter, r *http.Request) {
	// xss-response-request: request data written into the response body
	fmt.Fprintf(w, "<h1>%s</h1>", r.URL.Query().Get("name"))
}

func restore(w http.ResponseWriter, r *http.Request) {
	// unsafe-deserialization: native decoder on untrusted input
	dec := gob.NewDecoder(r.Body)
	var state map[string]string
	dec.Decode(&state)
}
