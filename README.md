# livereload-c

An implementation of the LiveReload server in C (libwebsocket)

imitated the  [LiveReloadX](https://github.com/nitoyon/livereloadx).

## Dependencies

json processing is not using the jansson library.

* [jansson](http://www.digip.org/jansson/)

libwebsockets C library for lightweight websocket clients and servers.

* [libwebsockets](http://libwebsockets.org)

livereload.js of [LiveReloadX](https://github.com/nitoyon/livereloadx) is
required for operation.

* [livereload.js](https://github.com/nitoyon/livereloadx/blob/master/contrib/livereload.js)


## Build

required.

* [cmake](http://www.cmake.org)
* [libwebsockets](http://libwebsockets.org)
* [jansson](http://www.digip.org/jansson/) (optional)
* [inotify-tools](http://inotify-tools.sourceforge.net/) (optional)

```
% cmake .
% make
% make install
```

## Application

 command           | description
 -------           | -----------
 livereload-server | server application
 livereload-client | client application
 livereload-filter | contents filter application

## Run

### Server

default bind port is 35729.

```
% livereload-server [-p 35729]
```

simple httpd server and livereload.js filter.

```
% livereload-server -R /path/to/resource -s ./livereload.js
```

/path/to/resource/index.html:

```
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>TEST</title>
</head>
<body>
Hello, World.
</body>
</html>
```

show `http://localhost:35729` in the browser

```
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Index</title>
<script type="text/javascript" src="/livereload.js"></script>
</head>
```

`livereload.js` script in front of `</head>` is output.

the other option confirm `--help`.

### Client

default connect server is localhost.

default connect port is 35729.

send to file name.

```
% livereload-client [-a localhost] [-p 35729] test.html
#--> {"command":"reload","path":"test.html"}
```

add a web host. (-h, --host)

```
% livereload-client -h localhost test.html
#--> {"command":"reload","path":"http://localhost/test.html"}
```

remove suffix string. (-s, --suffix)

```
% livereload-client -h localhost -s .html test.html
#--> {"command":"reload","path":"http://localhost/test"}
```

watcing the directory of change file.

```
% livereload-client -h localhost -w /path/to/dirctory
```

the other option confirm `--help`.

### Filter

filter of web server.

```
# LiveReload
ExtFilterDefine livereload mode=output intype=text/html cmd="/path/to/livereload-filter -q http://localhost/livereload.js"
```

output `<script type="text/javascript" src="http://localhost/livereload.js"></script>` before `</head>`.

the other option confirm `--help`.
