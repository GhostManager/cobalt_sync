FROM golang:1.20-bookworm

WORKDIR /usr/src/app
ARG GOPROXY
ARG GO111MODULE

RUN go env -w GOPROXY=${GOPROXY}
RUN go env -w GO111MODULE=${GO111MODULE}

COPY ["src/", "."]

RUN CGOENABLED=0 go build -ldflags="-s -w -X 'github.com/GhostManager/cobalt_sync/cmd/config.Version=`git describe --tags --abbrev=0`' -X 'github.com/GhostManager/cobalt_sync/cmd/config.BuildDate=`date -u '+%d %b %Y'`'" -o cobalt-parser && cp ./cobalt-parser /cobalt-parser

CMD ["/bin/sh", "-c", "/cobalt-parser $COBALT_PARSER_COMMAND"]