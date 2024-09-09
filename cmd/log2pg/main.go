package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/lib/pq"
)

type LogReceiver struct {
	InsertStatement *sql.Stmt
	AddURL          bool
	AllowedOrigins  map[string]bool
}

type ArrayVarType []string

func (vt *ArrayVarType) String() string {
	return strings.Join(*vt, ", ")
}

func (vt *ArrayVarType) Set(v string) error {
	*vt = append(*vt, v)
	return nil
}

func (lr LogReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	allowOrigin := lr.AllowedOrigins == nil
	if !allowOrigin && lr.AllowedOrigins[origin] {
		allowOrigin = true
	}
	if !allowOrigin {
		log.Printf("Rejected %d bytes via %s to %s from %s %v",
			r.ContentLength, r.Method, r.RequestURI, r.RemoteAddr, r.Header)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Method == "OPTIONS" && origin != "" && r.Header.Get("Access-Control-Request-Method") != "" {
		w.Header().Add("Access-Control-Allow-Origin", origin)
		w.Header().Add("Access-Control-Allow-Methods", "POST")
		if rqh := r.Header.Get("Access-Control-Request-Headers"); rqh != "" {
			w.Header().Add("Access-Control-Allow-Headers", rqh)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Body == http.NoBody {
		log.Printf("No body received from %s", r.RemoteAddr)
	} else if body, err := io.ReadAll(r.Body); err != nil {
		log.Printf("Could not read body")
	} else {
		var insertId int
		insertArgs := []interface{}{r.RemoteAddr, string(body)}
		if lr.AddURL {
			insertArgs = append(insertArgs, r.RequestURI)
		}
		if err := lr.InsertStatement.QueryRow(insertArgs...).Scan(&insertId); err != nil {
			log.Printf("Error executing statement: %s, args: %#v", err, insertArgs)
		} else {
			log.Printf("Received log entry #%d from %s", insertId, r.RemoteAddr)
			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
			w.Header().Set("Content-Type", "application/json")
			d, err := json.Marshal(insertId)
			if err != nil {
				log.Printf("error encoding %#v to response: %s", insertId, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if _, err := w.Write(d); err != nil {
				log.Printf("error writing response: %s", err)
			}
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
	var origins ArrayVarType
	flag.Var(&origins, "origin", "allowed origins (multi-arg)")
	tableCreateSql := flag.String("create", "CREATE TABLE \"%s\" (id BIGSERIAL PRIMARY KEY, stamp TIMESTAMPTZ DEFAULT now(), url text, src text, msg JSONB)", "Table creation SQL")
	flag.Parse()

	db, err := sql.Open("postgres", *dsn)
	if err != nil {
		log.Fatalf("Cannot connect to database %#v: %s", *dsn, err)
	}
	returnValue := "id"
	if _, err := db.Exec(fmt.Sprintf("SELECT 1 FROM \"%s\" WHERE 1=0 AND src IS NOT NULL and msg IS NOT NULL", *dbTable)); err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code.Name() == "undefined_table" {
			if _, err := db.Exec(fmt.Sprintf(*tableCreateSql, *dbTable)); err != nil {
				log.Fatalf("Creating table %#v failed: %s\n", *dbTable, err)
			}
			log.Printf("Created table %#v in database", *dbTable)
		} else if pqErr, ok := err.(*pq.Error); ok && pqErr.Code.Name() == "insufficient_privilege" {
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

	listenProto := "tcp"
	if (*listenFlag)[:1] == "/" || (*listenFlag)[:1] == "@" || (*listenFlag)[:2] == "./" {
		listenProto = "unix"
		if (*listenFlag)[:1] != "@" {
			_ = os.Remove(*listenFlag)
		}
	}

	log.Printf("Listening on %s", *listenFlag)
	ln, err := net.Listen(listenProto, *listenFlag)
	if err != nil {
		log.Fatalf("Listen on %#v failed: %s", *listenFlag, err)
	}
	var originMap map[string]bool
	for _, origin := range origins {
		if originMap == nil {
			originMap = map[string]bool{}
		}
		originMap[origin] = true
	}

	if err := http.Serve(ln, LogReceiver{InsertStatement: sqlInsert, AddURL: haveUrl, AllowedOrigins: originMap}); err != nil {
		log.Fatalf("Could not start HTTP server: %s", err)
	}
}
