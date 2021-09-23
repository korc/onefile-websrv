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

- `-map` option in `hostname/path=handler:params` format can be used to map different paths to different handlers
  - optional `hostname` can be used for virtual hosting, empty value for all hosts
- additional `-map` entries add more mappings
- supported `handler` types:
  - `file:` statically serve files from directory specified in `params`, or current working directory if empty
  - `webdav:` WebDAV handler for directory `params`, or memory-only storage if empty
  - `websocket:` (alias `ws`) connects a websocket to TCP or UNIX socket
  - `http:` pass request to HTTP backend
  - `debug:` client request debug
  - `cgi:` Run a CGI script specified by `params`.
  - `jwt:` generate JWT token

#### WebSocket handler

- `params` contains target where websocket is connected to
  - `HOST:PORT` or `tcp:HOST:PORT` to connection via TCP to _HOST:PORT_
  - `tls:HOST:PORT` to connect using TLS over TCP
  - `unix:/PATH/SOCKET` for UNIX socket
  - `exec:COMMAND` to run COMMAND using `sh -c`
    - prefix `{sh=SHELL}` for alternate shell
    - prefix `{no-c=1}` for no `-c` option after shell command
    - prefix `{sep=SEPARATOR}` to split string after `exec:` into arguments with _SEPARATOR_
  - `mux:ID` to share a websocket with other clients connected to the same `ID`
- supported options before path in `{...}`
  - `type=text` to change default message type to text
  - `re=REGEXP` to match grouped params like `$1` in address from request URL path with regexp

#### HTTP handler

- `params` must be complete URL starting with `http:`, `https:` or `unix:`
- supports unix sockets in the format of `unix:///path/to/unix-socket:/urlpath`
- comma-separated options between `{...}` before URL:
  - `cert` and `key` options to set TLS backend client certificate and key files
  - forward client certificate data to backend in specified HTTP header:
    - `fp-hdr` SHA256 fingerprint
    - `cn-hdr` subject CN attribute
    - `subj-hdr` subject in text form
    -  `cert-hdr` hex-encoded client certificate

#### Debug handler

Includes client certificate hash, which can be used for `-auth` option's `Cert` method

#### CGI handler

Before program name, can specify environment and args with `{` `}`

##### Examples

- `{AAAA,BBBB=123,arg:--dir,arg:/var/www}/usr/lib/cgi/program`
  - `AAAA` will be copied from host env, `BBBB` will be set to `123`, program will be executed with 2 arguments: `--dir` and `/var/www`

#### JWT handler

- secret source specified by `params`
- source can be prefixed with `file:` to read source from file, or `env:` to read from environment variable
- following comma-separated options can prefixed with `{...}` before source
  - `b64=1` decode secret from base64
  - `alg={ES256|ES384|ES512|RS256|RS384|RS512|PS256|PS384|PS512|HS256|HS384|HS512}` generation algorithm
    - default algorithm is `HS256`
    - `RS*` and `PS*` source must be PEM-encoded RSA private key (PKCS#1)
    - `ES*` source is EC-DSA key
  - `<key>=<value>`: set `key` in the issued claim to `value`
    - if `key` ends with `_claim`, that is removed
    - `value` can be value string, or prefixed with following:
      - `str:` plain string following `str:`
      - `crt:` client certificate data
        - `cn` subject common name
        - `subj` full subject
        - `fp` certificate sha256 fingerprint
        - `crt` base64-encoded certificate
      - `q:` URL query value
      - `post:` POST form value
      - `hdr:` HTTP request header
      - `env:` server environment variable
      - `req:` a value from request parameter
        - `raddr` client remote address (with port number)
        - `rip` client remote IP
        - `host` requested Host
      - `ts:` unix timestamp value
        - basic format is `+duration` or `-duration` to add or substract from current time
        - can prefix duration with
          - `today` to make relation based on start of the day in server localtime
          - `q:` get duration relative to issue time from URL query
    - `exp` is by default set to `ts:+5m`, use `exp=` with empty value to explicitly disable JWT expiration

##### Examples:

- `-map /acl/get=jwt:{b64=1,exp=ts:+1h,aud=q:target,nbf=ts:q:nbf}bXktc2VjcmV0`
  - HS256 signed with shared secret `my-secret`, 1 hour expiration, audience from `target` query parameter, valid-from time from `nbf` query parameter (default=time of request)
- `-map /login=jwt:{exp=ts:today+25h,sub=crt:cn,alg=ES256}file:jwt.key`
  - signed with EC-DSA key in `jwt.key`, `sub` in claims from client's x509 certifiate subject `CN` attribute, expiring on next day at 1am

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
       `file:` prefix make keys to be loaded from specified file instead
         - can read OpenSSH `authorized_keys` with `ssh-rsa` keys, and PEM files with `PUBLIC KEY` or `CERTIFICATE` data
    - `JWT`
      - `auth` value is RSA or ECDSA private or public key in PEM format, unless `{hs=1}` option is given
        - use `env:<varname>` or `file:<filename>` to read value from environment or file
      - `{..}` options values
        - `query=<name>`, `cookie=<name>`, `header=<name>` look for JWT token from those places as well, in addition to `Authentication: Bearer ...` header
        - `hs=1` use `auth` value as secret key for HMAC signature
        - `b64=1` decode `auth` value with base64
        - `aud=<type>:<value>` or `aud=path` - determine what is going to be checked for `aud` "*Audience*" claim
          - `type` and `value` use same syntax as claim string values in [JWT handler](#jwt-handler) (no `ts:` timestamp).
        - `aud-re=<regexp>` aud value (`path` by default, can be overwritten by `aud=`) will be matched against regexp, if subgroups found then first group will be used as value
    - `JWTSecret` *DEPRECATED* in favor of `JWT`
      - checks if JWT from `Authentication: Bearer` header is signed by specific authority
      - `auth` contains authority's shared secret
      - can prefix `auth` with `{cookie|header|query=XXX}` to additionally look JWT token from specified cookie, header or query parameter named `XXX`. multiple locations have to be separated with comma.
        - ex: `-auth viewer=JWTSecret:{cookie=viewacces,query=va}MySecretJWTKey`
    - `IPRange`
      - checks client's remote IP
      - `auth` is IP address with network mask length in format of `ip/masklen`
    - `JWTFilePat` *DEPRECATED*
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
    - `File`
      - file existance check
      - options available with `{..}` prefix:
        - `nofile` inverse condition, and succeed if file does NOT exist
        - `re-path` treat auth value as regular expression, and `re-path` as pathname with `$<nr>` subgroup expansion pattern
          - ex: `-map /=webdav:/data/ -auth nofile=File:{no-file=1,re-path=/data/$1}/(.+) -auth ip4all=IPRange:0.0.0.0/0 -acl {PUT}^/=nofile -acl {GET}^/=ip4all -acl ^/=nobody`
            - create a WebDAV mapping for `/data/`, where you can upload only new files
