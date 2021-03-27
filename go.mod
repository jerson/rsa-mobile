module github.com/jerson/rsa-mobile

go 1.13

require (
	github.com/gogo/protobuf v1.3.2
	github.com/google/flatbuffers v1.12.0
	github.com/lestrrat-go/jwx v1.0.2
	github.com/stretchr/testify v1.5.1
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
	software.sslmate.com/src/go-pkcs12 v0.0.0-20200408181440-2981468c0ff3
)

replace github.com/lestrrat-go/jwx => github.com/lestrrat-go/jwx v1.0.2

replace github.com/stretchr/testify => github.com/stretchr/testify v1.5.1

replace software.sslmate.com/src/go-pkcs12 => software.sslmate.com/src/go-pkcs12 v0.0.0-20200408181440-2981468c0ff3

replace golang.org/x/crypto => golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
