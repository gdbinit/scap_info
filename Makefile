
BUILD_VERSION=0.1.0
BUILD_GITHASH=$(shell git rev-parse --short HEAD)
BUILD_NUMBER=$(shell git log --pretty=oneline | wc -l | tr -d " ")
BUILD_DATE=$(shell date -u "+%Y-%m-%dT%H:%M:%SZ")

LDFLAGS += -X 'main.GitHash=${BUILD_GITHASH}'
LDFLAGS += -X 'main.Build=${BUILD_NUMBER}'
LDFLAGS += -X 'main.Time=${BUILD_DATE}'

.PHONY: scap_info clean

all: scap_info

scap_info: clean
	@echo ">  Building..."
	@env go build -o $@ -ldflags="${LDFLAGS}"
	@echo ">  Done..."

clean:
	@rm -f scap_info
