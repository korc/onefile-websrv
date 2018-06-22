# README

## Installing

For lazy people: `go run websrv.go -listen :8080`

For more systematic installation:
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

```
websrv -h
  -acl value
    	<path_regexp>=<role>[+<role2..>]:<role..> (multival-arg)
  -acmehost string
    	Autocert hostnames (comma-separated), -cert will be cache dir
  -acmehttp string
    	Listen address for ACME http-01 challenge (default ":80")
  -auth value
    	[<role>[+<role2>]=]<method>:<auth> (multivalue-arg)
  -cert string
    	SSL certificate file / autocert cache dir
  -chroot string
    	chroot() to directory
  -key string
    	SSL key file
  -listen string
    	Listen ip:port (default ":80")
  -map value
    	<path>=<handler>:[<params>] (multival-arg, default '/=file:')
  -user string
    	Switch to user (NOT RECOMMENDED)
  -wdctype string
    	Fix content-type for Webdav GET/POST requests
```
Options marked as `multival-arg` can be specified multiple times on commandline, and will add to existing configuration.
