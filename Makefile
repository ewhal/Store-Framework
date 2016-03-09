## simple makefile to log workflow
.PHONY: all test clean build install mkdirs concat-css concat-js min-css min-js copy

GOFLAGS ?= $(GOFLAGS:)

all: clean install build mkdirs copy concat-css concat-js min-css min-js

mkdirs:
	@mkdir -p ./build/css
	@mkdir -p ./build/js

concat-css:
	@cat ./static/css/bootstrap.css ./static/css/font-awesome.css ./static/css/main.css  ./static/css/creative.css ./static/css/style.css> ./build/css/main.css.tmp


concat-js:
	@cat ./static/js/*\.js > ./build/js/main.js.tmp

min-css:
	@node ./node_modules/.bin/cleancss ./build/css/main.css.tmp > ./build/css/main.min.css && rm ./build/css/main.css.tmp

min-js:
	@node ./node_modules/.bin/uglifyjs ./build/js/main.js.tmp > ./build/js/main.min.js && rm ./build/js/main.js.tmp

copy:
	@cp -r ./static/img/ ./build/img
	@cp -r ./static/fonts/ ./build/fonts

build:
	@go build $(GOFLAGS) ./...

install:
	@go get $(GOFLAGS) ./...

test: install
	@go test $(GOFLAGS) ./...

bench: install
	@go test -run=NONE -bench=. $(GOFLAGS) ./...

clean:
	@go clean $(GOFLAGS) -i ./...
	@rm -rf ./build 
