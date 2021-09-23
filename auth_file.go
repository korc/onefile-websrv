package main

import (
	"errors"
	"net/http"
	"os"
	"regexp"
	"strconv"
)

func init() {
	addAuthMethod("File", func(check string, roles []string) (Authenticator, error) {
		return newFileAuthenticator(check, roles)
	})
}

type FileAuthenticator struct {
	PathTemplate string
	NoFile       bool
	FilePath     string
	PathRe       *regexp.Regexp
	roles        []string
}

var ErrNoSubgroups = errors.New("no subgroup references")

func newFileAuthenticator(check string, roles []string) (fa *FileAuthenticator, err error) {
	fa = &FileAuthenticator{roles: roles}
	options, check := parseCurlyParams(check)
	var haveOpt bool
	if fa.PathTemplate, haveOpt = options["re-path"]; haveOpt {
		fa.PathRe, err = regexp.Compile(check)
		if err != nil {
			logf(nil, logLevelFatal, "Cannot compile %#v as regular expression: ", err)
			return nil, err
		}
		if !subgroupMatchRe.MatchString(fa.PathTemplate) {
			logf(nil, logLevelFatal, "re-path option does not contain any $<nr> subgroup references")
			return nil, ErrNoSubgroups
		}
	} else {
		fa.FilePath = check
	}
	if nfStr, haveOpt := options["nofile"]; haveOpt {
		if fa.NoFile, err = strconv.ParseBool(nfStr); err != nil {
			logf(nil, logLevelFatal, "nofile parameter is not boolean")
			return
		}
	}
	return fa, nil
}

func (fa *FileAuthenticator) hasRequestedRoles(rolesToCheck map[string]interface{}) bool {
	for _, role := range fa.roles {
		if _, inRequested := rolesToCheck[role]; inRequested {
			return true
		}
	}
	return false
}

func (fa *FileAuthenticator) GetRoles(req *http.Request, rolesToCheck map[string]interface{}) (roles []string, err error) {
	roles = make([]string, 0)
	if rolesToCheck != nil && !fa.hasRequestedRoles(rolesToCheck) {
		return
	}

	filePath := fa.FilePath
	if fa.PathRe != nil {
		match := fa.PathRe.FindStringSubmatch(req.URL.Path)
		if match == nil {
			return
		}
		grpNumErr := 0
		filePath = subgroupMatchRe.ReplaceAllStringFunc(fa.PathTemplate, func(s string) string {
			grp, _ := strconv.ParseInt(s[1:], 10, 0)
			if int(grp) >= len(match) {
				grpNumErr = int(grp)
				return s
			}
			return match[grp]
		})
		if grpNumErr > 0 {
			logf(req, logLevelError, "Filepath ACL regexp match %#v for %#v does not enough groups: %#v", match, roles, grpNumErr)
			return
		}
	}
	_, statErr := os.Stat(filePath)
	if (statErr == nil && !fa.NoFile) || (fa.NoFile && statErr != nil && os.IsNotExist(statErr)) {
		roles = append(roles, fa.roles...)
	}

	return
}
