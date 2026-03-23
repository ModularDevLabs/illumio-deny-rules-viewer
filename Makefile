APP     := deny-rules
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)
DISTDIR := dist
DIST_STAMP := $(DISTDIR)/.stamp
SRCS := $(shell find . -type f \( -name '*.go' -o -path './templates/*' -o -path './static/*' -o -name 'go.mod' -o -name 'go.sum' \))

.PHONY: run build dist clean tidy

run:
	go run . -addr :8082

build: $(SRCS)
	go build -ldflags "$(LDFLAGS)" -o $(APP) .

dist: $(DISTDIR)/$(APP)-linux-amd64 $(DISTDIR)/$(APP)-linux-arm64 \
      $(DISTDIR)/$(APP)-darwin-amd64 $(DISTDIR)/$(APP)-darwin-arm64 \
      $(DISTDIR)/$(APP)-windows-amd64.exe

$(DISTDIR)/$(APP)-linux-amd64: $(SRCS) | $(DIST_STAMP)
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $@ .

$(DISTDIR)/$(APP)-linux-arm64: $(SRCS) | $(DIST_STAMP)
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $@ .

$(DISTDIR)/$(APP)-darwin-amd64: $(SRCS) | $(DIST_STAMP)
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $@ .

$(DISTDIR)/$(APP)-darwin-arm64: $(SRCS) | $(DIST_STAMP)
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $@ .

$(DISTDIR)/$(APP)-windows-amd64.exe: $(SRCS) | $(DIST_STAMP)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $@ .

$(DIST_STAMP):
	mkdir -p dist
	touch $@

tidy:
	go mod tidy

clean:
	rm -rf $(DISTDIR)/ $(APP)
