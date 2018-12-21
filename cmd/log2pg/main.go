package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/lib/pq"
)

type LogReceiver struct {
	InsertStatement *sql.Stmt
}

func (lr LogReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if body, err := ioutil.ReadAll(r.Body); err != nil {
		log.Printf("Could not read body")
	} else {
		var insertId int
		if err := lr.InsertStatement.QueryRow(r.RemoteAddr, string(body)).Scan(&insertId); err != nil {
			log.Printf("Error executing statement: %s", err)
		} else {
			log.Printf("Received log entry #%d from %s", insertId, r.RemoteAddr)
			w.WriteHeader(http.StatusNoContent)
			return
		}

	}
	w.WriteHeader(http.StatusBadRequest)
}

func main() {
	listenFlag := flag.String("listen", "127.0.0.1:8003", "Listen for log messages on IP")
	dsn := flag.String("dsn", "sslmode=disable", "Postgresql DSN")
	dbTable := flag.String("table", "log", "Table in database receiving log")
	tableCreateSql := flag.String("create", "CREATE TABLE \"%s\" (id BIGSERIAL PRIMARY KEY, stamp TIMESTAMPTZ DEFAULT now(), src text, msg JSONB)", "Table creation SQL")
	flag.Parse()

	db, err := sql.Open("postgres", *dsn)
	if err != nil {
		log.Fatalf("Cannot connect to database %#v: %s", *dsn, err)
	}
	if _, err := db.Exec(fmt.Sprintf("SELECT 1 FROM \"%s\" WHERE 1=0 AND src IS NOT NULL and msg IS NOT NULL", *dbTable)); err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "42P01" {
			if _, err := db.Exec(fmt.Sprintf(*tableCreateSql, *dbTable)); err != nil {
				log.Fatalf("Creating table %#v failed: %s\n", *dbTable, err)
			}
			log.Printf("Created table %#v in database", *dbTable)
		} else {
			log.Fatalf("Could not access table %#v: %s\n", *dbTable, err)
		}
	}
	insertTmpl := "INSERT INTO \"%s\" (src, msg) VALUES ($1, $2) RETURNING id"
	sqlInsert, err := db.Prepare(fmt.Sprintf(insertTmpl, *dbTable))
	if err != nil {
		log.Fatal("Cannot prepare query: ", err)
	}
	defer sqlInsert.Close()

	log.Printf("Listening on %s", *listenFlag)
	if err := http.ListenAndServe(*listenFlag, LogReceiver{InsertStatement: sqlInsert}); err != nil {
		log.Fatalf("Could not start HTTP server: %s", err)
	}
}
