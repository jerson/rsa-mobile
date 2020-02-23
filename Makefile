default: fmt test

deps: 
	go mod download

test:
	go test ./...

fmt:
	go fmt ./...

all: binding android ios wasm

.PHONY: wasm
wasm:
	mkdir -p output/wasm
	GOARCH=wasm GOOS=js go build -ldflags="-s -w" -o output/wasm/rsa.wasm wasm/main.go
	cp output/wasm/rsa.wasm wasm/sample/public/rsa.wasm

binding: deps
	mkdir -p output/binding
	go build -ldflags="-s -w" -o output/binding/rsa.so -buildmode=c-shared binding/main.go

android: deps
	mkdir -p output/android
	gomobile bind -ldflags="-w -s" -target=android -o output/android/rsa.aar github.com/jerson/rsa-mobile/rsa

ios: deps
	mkdir -p output/ios
	gomobile bind -ldflags="-w -s" -target=ios -o output/ios/Rsa.framework github.com/jerson/rsa-mobile/rsa
