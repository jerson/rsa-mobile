module github.com/jerson/rsa-mobile

go 1.13

require (
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

replace golang.org/x/net => golang.org/x/net v0.0.0-20190620200207-3b0461eec859

replace golang.org/x/sync => golang.org/x/sync v0.0.0-20201020160332-67f06af15bc9

replace golang.org/x/sys => golang.org/x/sys v0.0.0-20190215142949-d0b11bdaac8a
