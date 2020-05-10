BINDING_FILE?=rsa.so

default: fmt test

deps: 
	go mod download

test:
	go test ./... -coverprofile=profile.cov -cover -short -count 1

fmt:
	go fmt ./...

clean:
	rm -rf output

all: clean binding android ios wasm

gomobile:
	GO111MODULE=off go get golang.org/x/mobile/cmd/gomobile
	gomobile init

.PHONY: wasm
wasm:
	mkdir -p output/wasm
	GOARCH=wasm GOOS=js go build -ldflags="-s -w" -o output/wasm/rsa.wasm wasm/main.go
	cp output/wasm/rsa.wasm wasm/sample/public/rsa.wasm

android: deps
	mkdir -p output/android
	gomobile bind -ldflags="-w -s" -target=android -o output/android/rsa.aar github.com/jerson/rsa-mobile/rsa

ios: deps
	mkdir -p output/ios
	gomobile bind -ldflags="-w -s" -target=ios -o output/ios/Rsa.framework github.com/jerson/rsa-mobile/rsa

swig:
	swig -go -cgo -c++ -intgosize 64 binding/rsa_bridge/rsa_bridge.i

binding_all: binding_windows binding_linux

binding_linux: binding_linux_386 binding_linux_amd64 binding_linux_arm64 binding_linux_armv7

binding_linux_386:
	GOOS=linux GOARCH=386 TAG=main \
	ARGS="-e BINDING_FILE=linux_386_rsa.so" \
	CMD="make binding" ./cross_build.sh

binding_linux_amd64:
	GOOS=linux GOARCH=amd64 TAG=main \
	ARGS="-e BINDING_FILE=linux_amd64_rsa.so" \
	CMD="make binding" ./cross_build.sh

binding_linux_arm64:
	GOOS=linux GOARCH=arm64 TAG=arm \
	ARGS="-e BINDING_FILE=linux_arm64_rsa.so" \
	CMD="make binding" ./cross_build.sh

binding_linux_armv7:
	GOOS=linux GOARCH=armv7 TAG=arm \
	ARGS="-e BINDING_FILE=linux_armv7_rsa.so" \
	CMD="make binding" ./cross_build.sh

binding_windows: binding_windows_386 binding_windows_amd64

binding_windows_386:
	GOOS=windows GOARCH=386 \
	ARGS="-e BINDING_FILE=windows_386_rsa.dll" \
	TAG=main CMD="make binding" ./cross_build.sh

binding_windows_amd64:
	GOOS=windows GOARCH=amd64 TAG=main \
	ARGS="-e BINDING_FILE=windows_amd64_rsa.dll" \
	CMD="make binding" ./cross_build.sh

binding: deps
	mkdir -p output/binding
	go build -ldflags="-w" -o output/binding/$(BINDING_FILE) -buildmode=c-shared binding/main.go