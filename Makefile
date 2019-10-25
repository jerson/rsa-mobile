

default: fmt test


test:
	go test ./...

fmt:
	go fmt ./...

android:
	gomobile bind -ldflags="-w -s" -target=android -o rsa.aar github.com/jerson/rsa-mobile/mobile


ios:
	gomobile bind -ldflags="-w -s" -target=ios -o Rsa.framework github.com/jerson/rsa-mobile/mobile
