# README

## Installing

### For lazy people (who have Go)

```sh
go get -u github.com/korc/onefile-websrv
go/bin/onefile-websrv -listen :8080
```

### With Docker

Serving content from `/data/web/html`:

```sh
docker build -t websrv https://github.com/korc/onefile-websrv.git
docker run --name websrv -u 33:33 -p 80:8080 -v /data/web:/var/www websrv -listen :8080
```

### For more systematic installation

```sh
go build -o websrv websrv.go
install websrv /usr/local/bin
install -m 0644 websrv.service /etc/systemd/system/
vi /etc/systemd/system/websrv.service
systemctl daemon-reload
systemctl enable websrv
systemctl start websrv
systemctl status websrv
```

### Listening on low-number ports, chroot and non-root user issues

websrv can change user id after start (required for low-level port listen and chroot), but unfortunately that's currently broken in Golang's Linux implementation (some process threads might remain running as `root`). If you don't want to run as `root` (not recommended anyway), and want to use those high-privileged functions, then it's best to set appropriate `capabilities(7)` with `setcap(8)` program (ex: `setcap cap_net_bind_service,cap_sys_chroot=ep websrv`), and then run as target user (ex: `www-data`).

## Configuration

### Command-line options

```text
websrv -h
  -acl value
      [{<methods..>}]<path_regexp>=<role>[+<role2..>]:<role..> (multi-arg)
  -acmehost string
      Autocert hostnames (comma-separated), -cert will be cache dir
  -acmehttp string
      Listen address for ACME http-01 challenge (default ":80")
  -auth value
      [<role>[+<role2>]=]<method>:<auth> (multi-arg)
  -cert string
      SSL certificate file or autocert cache dir
  -chroot string
      chroot() to directory after start
  -key string
      SSL key file
  -listen string
      Listen ip:port (default ":80")
  -loglevel string
      Max log level (one of FATAL, ERROR, WARNING, INFO, VERBOSE, DEBUG) (default "info")
  -map value
      <path>=<handler>:[<params>] (multi-arg, default '/=file:')
  -user string
      Switch to user (NOT RECOMMENDED)
  -wdctype string
      Fix content-type for Webdav GET/POST requests
  -cors value
      <path>=<allowed_origin> (multi-arg)
  -wstmout int
      Websocket alive check timer in seconds (default 60)
  -reqlog string
      URL to log request details to
```

Options marked with `multi-arg` can be specified multiple times on commandline, and will add to previous configuration. Other options are meant to be set only once.

### URL path mapping

- `-map` option can be used to map URL's to different handlers
- multiple arguments on command-line will add more mappings
- each mapping has relative URL `path` and `handler` part, with optional `parameters` for each handler type
- `handler` parameter values:
  - `file`
    - simple file-based static webserver
    - `params` is a filesystem directory path
    - empty `params` means "current directory"
  - `webdav`
    - webdav handler file downloads/uploads
    - make sure you use proper authetication
    - `params` is a filesystem directory path
  - `websocket` (alias `ws`)
    - connects a websocket to TCP or UNIX socket
    - `params` will be `IP:PORT` for TCP, or `unix:/path/socket` for UNIX socket connection
  - `http`
    - pass-thru proxy
    - `params` is a full URL of backend web server
    - `params` can be prefixed with comma-separated connection options between `{` and `}`
      - `cert` and `key` options to set TLS client cert/key files
  - `debug`
    - client request debugging
    - shows also client certificate hash, which can be used for `-auth` option's `Cert` method
  - `cgi`
    - Run a CGI script specified by `params`.
    - Before program name, can specify environment and args with `{` `}`
      - Example: `{AAAA,BBBB=123,arg:--dir,arg:/var/www}/usr/lib/cgi/program`
        - `AAAA` will be copied from host env, `BBBB` will be set to `123`, program will be executed with 2 arguments:
         `--dir` and `/var/www`

### Access control

- `-acl` option will define mapping between URL paths and required roles
  - path is defined by regular expression
  - you can specify HTTP methods (GET, POST etc) separated with commas in curly braces before path regexp
  - `:` separates alternate roles (OR operation)
  - `+` makes all specified roles to be required (AND operation)
    - can be used to implement multi-factor auth
- `-auth` option can be used to add new roles
  - multiple roles can be assigned with one method
  - `auth` value is method-specific
  - possible values for `method` parameter
    - `Basic`
      - HTTP Basic authentication (WEAK security)
      - `auth` is a Base64-encoded value of `username:password`
    - `Cert`
      - SSL Client X.509 certificate authentication
      - `auth` as hex-encoded value of SHA-256 hash of certificate's binary (DER) data
      - if `auth` starts with `file:`, certificate is read from file on disk and it's hash is used instead
    - `CertBy`
      - `auth` can be hex-encoded value of client CA certificate's binary
      - `file:` in the beginning of `auth` will load CA certificate from file
    - `JWTSecret`
      - checks if JWT from `Authentication: Bearer` header is signed by specific authority
      - `auth` contains authority's shared secret
    - `IPRange`
      - checks client's remote IP
      - `auth` is IP address with network mask length in format of `ip/masklen`
