# README

## Installing

### Quick-start examples

#### Serving current directory on port 8080

(You need [Go](https://golang.org/dl/) to be installed)

```sh
go get -u github.com/korc/onefile-websrv
go/bin/onefile-websrv -listen :8080
```

#### Public HTTPS server with valid, auto-generated Let's Encrypt certificates

(replace `example.com` with your real public hostname)

```sh
go get -u github.com/korc/onefile-websrv
mkdir acme-certs
sudo go/bin/onefile-websrv -listen :443 -acmehost example.com -cert $PWD/acme-certs -map /=file:/var/www
```

Check out systemd approach below for more secure setup.

#### With Docker

Serving content from `/data/web/html`:

```sh
docker build -t websrv https://github.com/korc/onefile-websrv.git
docker run --name websrv -u 33:33 -p 80:8080 -v /data/web:/var/www websrv -listen :8080
```

### For more systematic installation

```sh
apt-get install libcap2-bin
go get -u github.com/korc/onefile-websrv
install go/bin/onefile-websrv /usr/local/bin/websrv
install -m 0644 go/src/github.com/korc/onefile-websrv/websrv.service /etc/systemd/system/
vi /etc/systemd/system/websrv.service
systemctl daemon-reload && systemctl enable websrv && systemctl start websrv
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
  -cert-fallback
      Certificate file to use if ACME fails
  -chroot string
      chroot() to directory after start
  -key string
      SSL key file
  -listen string
      Listen ip:port or /path/to/unix-socket (default ":80")
  -loglevel string
      Max log level (one of FATAL, ERROR, WARNING, INFO, VERBOSE, DEBUG) (default "info")
  -map value
      [<vhost>]/<path>=<handler>:[<params>] (multi-arg, default '/=file:')
  -user string
      Switch to user (NOT RECOMMENDED)
  -wdctype string
      Fix content-type for Webdav GET/POST requests
  -cors value
      <path>=<allowed_origin> (multi-arg)
  -wstmout int
      Websocket alive check timer in seconds (default 60)
  -reqlog string
      URL to log request details to (supports also unix:///dir/unix-socket:/path URLs)
```

Options marked with `multi-arg` can be specified multiple times on commandline, and will add to previous configuration. Other options are meant to be set only once.

### URL path mapping

- `-map` option can be used to map URL's to different handlers
- multiple arguments on command-line will add more mappings
- each mapping has relative URL `path` and `handler` part, with optional `parameters` for each handler type
  - optionally prefix `path` with a host name for "virtual hosts"
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
    - `params` can be be
      - prefixed with `{type=text}` to change default message type to text
      - `HOST:PORT` to connection via TCP to _HOST:PORT_
      - `tls:HOST:PORT` to connect using TLS over TCP
      - `unix:/PATH/SOCKET` for UNIX socket
      - `exec:COMMAND` to run COMMAND using `sh -c`
        - prefix `{sh=SHELL}` for alternate shell
        - prefix `{no-c=1}` for no `-c` option after shell command
  - `http`
    - pass-thru proxy, full URL starting with `http:`, `https:` or `unix:`
    - `params` is a full URL of backend web server
      - supports webserver at unix socket in the format of `unix:///path/to/unix-socket:/urlpath`
    - `params` can be prefixed with comma-separated connection options between `{` and `}`
      - `cert` and `key` options to specify `https`-type backend client's cert/key files 
      - `fp-hdr`, `cn-hdr`, `subj-hdr` and `cert-hdr` options forward client-sent certificate SHA256 fingerprint,
       subject's CN attribute, subject's DN string or hex-encoded certificate to backend in specified HTTP header
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
  - `path_regexp` is defined by regular expression, like `^/admin/`
    - add `?` before regex (ex: `?^/xyz/.*session_id=.*`) to check full RequestURI including query part (not only Path) for match
  - in curly braces before path regexp can set comma-separated params
    - `host:<hostname>` to apply only for particular virtual hosts (req with `Host: hostname`)
    - `GET`, `POST`, etc. to filter by HTTP methods 
  - `:` separates alternate roles (OR operation)
  - `+` makes all specified roles to be required (AND operation)
    - can be used to implement multi-factor auth
- `-auth` option can be used to add new roles
  - multiple roles can be assigned with one method
  - `auth` value is method-specific
  - can use environment variables in form of `${variable_name}` in `auth` part (presence in environment is mandatory)
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
    - `CertKeyHash`
       `auth` is hex-encoded SHA256 hash of client certificate's public key (SHA256 of ASN1 from `ssh-keygen -e -m pkcs8` and `certtool --pubkey-info`)
       `file:` prefix makes keys to be loaded from specified file containing either PUBLIC KEY or CERTIFICATE data in PEM format
    - `JWTSecret`
      - checks if JWT from `Authentication: Bearer` header is signed by specific authority
      - `auth` contains authority's shared secret
    - `IPRange`
      - checks client's remote IP
      - `auth` is IP address with network mask length in format of `ip/masklen`
    - `JWTFilePat`
      - `auth` specifies file (pattern) containing accepted JWT tokens signed with:
        - secrets, in format of `hash:url-base64-encoded-secret`
        - RSA public keys, in format of `rsa:base64-encoded-n-value`
          - `e` is assumed to be `0x10001`
      - if letters "`**`" are found inside filename, they are replaced with pattern constructed from:
        - URL path, URL path with extensions of last element removed (one-by-one), and each path component removed one-by-one from the end
        - Ex: `-acl ^/adm/=xxx -auth xxx=JWTFilePat:/data/webauth/**.jwt` and access to `/adm/test.123.html` will result in checking of files
            - `/data/webauth/adm/test.123.html.jwt`
            - `/data/webauth/adm/test.123.jwt`
            - `/data/webauth/adm/test.jwt`
            - `/data/webauth/adm.jwt`
        - because of cost associatd checking for `.jwt` files, auth is applied only when path requires authentication
