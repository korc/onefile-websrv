package main

import (
	"log"
	"net/http"
	"regexp"
	"strings"
)

type ReSubst struct {
	Re       *regexp.Regexp
	Template string
	Target   string
}

func NewReSubst(s string) *ReSubst {
	sep := s[:1]
	parts := strings.SplitN(s, sep, 4)
	if len(parts) != 4 {
		log.Fatalf("regexp substitution string not in format @regexp@template@: %#v", s)
	}
	return &ReSubst{
		Re:       regexp.MustCompile(parts[1]),
		Template: parts[2],
		Target:   parts[3],
	}
}

func (rs *ReSubst) Subst(src string) string {
	dst := []byte{}
	for _, submatch := range rs.Re.FindAllStringSubmatchIndex(src, -1) {
		dst = rs.Re.ExpandString(dst, rs.Template, src, submatch)
	}
	return string(dst)
}

func (rs *ReSubst) SubstReq(r *http.Request) string {
	switch rs.Target {
	case "path", "":
		return rs.Subst(r.URL.Path)
	}
	log.Printf("unknown target: %#v", rs.Target)
	return ""
}
