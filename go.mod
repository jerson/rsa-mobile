module github.com/jerson/rsa-mobile

go 1.13

require (
	github.com/google/flatbuffers v2.0.6+incompatible
	github.com/lestrrat-go/jwx v1.0.2
	github.com/stretchr/testify v1.5.1
	golang.org/x/crypto v0.1.0
	software.sslmate.com/src/go-pkcs12 v0.0.0-20200408181440-2981468c0ff3
)

replace github.com/lestrrat-go/jwx => github.com/lestrrat-go/jwx v1.0.2

replace github.com/stretchr/testify => github.com/stretchr/testify v1.5.1

replace software.sslmate.com/src/go-pkcs12 => software.sslmate.com/src/go-pkcs12 v0.0.0-20200408181440-2981468c0ff3
