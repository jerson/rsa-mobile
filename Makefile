

default: fmt test

deps: 
	dep ensure -vendor-only

test:
	go test ./...

fmt:
	go fmt ./...

all: binding android ios

binding: deps
	mkdir -p output/binding
	go build -ldflags="-s -w" -o output/binding/rsa.so -buildmode=c-shared binding/main.go

android: deps
	mkdir -p output/android
	gomobile bind -ldflags="-w -s" -target=android -o output/android/rsa.aar github.com/jerson/rsa-mobile/rsa

ios: deps
	mkdir -p output/ios
	gomobile bind -ldflags="-w -s" -target=ios -o output/ios/Rsa.framework github.com/jerson/rsa-mobile/rsa
