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
	AddURL          bool
}

func (lr LogReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if body, err := ioutil.ReadAll(r.Body); err != nil {
		log.Printf("Could not read body")
	} else {
		var insertId int
		insertArgs := []interface{}{r.RemoteAddr, string(body)}
		if lr.AddURL {
			insertArgs = append(insertArgs, r.RequestURI)
		}
		if err := lr.InsertStatement.QueryRow(insertArgs...).Scan(&insertId); err != nil {
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
	addUrl := flag.Bool("add-url", true, "Add RequestURI to 'url' column if it exists")
	tableCreateSql := flag.String("create", "CREATE TABLE \"%s\" (id BIGSERIAL PRIMARY KEY, stamp TIMESTAMPTZ DEFAULT now(), url text, src text, msg JSONB)", "Table creation SQL")
	flag.Parse()

	db, err := sql.Open("postgres", *dsn)
	if err != nil {
		log.Fatalf("Cannot connect to database %#v: %s", *dsn, err)
	}
	returnValue := "id"
	if _, err := db.Exec(fmt.Sprintf("SELECT 1 FROM \"%s\" WHERE 1=0 AND src IS NOT NULL and msg IS NOT NULL", *dbTable)); err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "42P01" {
			if _, err := db.Exec(fmt.Sprintf(*tableCreateSql, *dbTable)); err != nil {
				log.Fatalf("Creating table %#v failed: %s\n", *dbTable, err)
			}
			log.Printf("Created table %#v in database", *dbTable)
		} else if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "42501" {
			log.Printf("Skipping table schema check, no permission to SELECT from %#v: %s", *dbTable, err)
			returnValue = "-1"
		} else {
			log.Fatalf("Could not access table %#v: %s\n", *dbTable, err)
		}
	}
	insertTmpl := "INSERT INTO \"%s\" (src, msg) VALUES ($1, $2) RETURNING " + returnValue
	haveUrl := false
	if *addUrl {
		if _, err := db.Exec(fmt.Sprintf("SELECT url FROM \"%s\" WHERE 1=0", *dbTable)); err == nil {
			insertTmpl = "INSERT INTO \"%s\" (src, msg, url) VALUES ($1, $2, $3) RETURNING " + returnValue
			haveUrl = true
			log.Printf("Logging also RequestURI")
		}
	}
	sqlInsert, err := db.Prepare(fmt.Sprintf(insertTmpl, *dbTable))
	if err != nil {
		log.Fatal("Cannot prepare query: ", err)
	}
	defer sqlInsert.Close()

	log.Printf("Listening on %s", *listenFlag)
	if err := http.ListenAndServe(*listenFlag, LogReceiver{InsertStatement: sqlInsert, AddURL: haveUrl}); err != nil {
		log.Fatalf("Could not start HTTP server: %s", err)
	}
}
