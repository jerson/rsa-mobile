package rsa

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_ConvertKeyPairToPKCS12(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.ConvertKeyPairToPKCS12(privateKey, certificate, password)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_ConvertKeyPairToPKCS12Complete(t *testing.T) {
	instance := NewFastRSA()
	pkcs12, err := instance.ConvertKeyPairToPKCS12(privateKey, certificate, password)
	if err != nil {
		t.Fatal(err)
	}

	output, err := instance.ConvertPKCS12ToKeyPair(pkcs12, password)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, privateKey, output.PrivateKey)
	assert.Equal(t, certificate, output.Certificate)

	encoded, _ := json.MarshalIndent(output, "", " ")
	t.Log("output:", string(encoded))
}

func TestFastRSA_ConvertKeyPairToPKCS12WithoutCert(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.ConvertKeyPairToPKCS12(privateKey, "", password)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_ConvertKeyPairToPKCS12CompleteWithoutCert(t *testing.T) {
	instance := NewFastRSA()
	pkcs12, err := instance.ConvertKeyPairToPKCS12(privateKey, "", password)
	if err != nil {
		t.Fatal(err)
	}

	output, err := instance.ConvertPKCS12ToKeyPair(pkcs12, password)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, privateKey, output.PrivateKey)

	encoded, _ := json.MarshalIndent(output, "", " ")
	t.Log("output:", string(encoded))
}

func TestFastRSA_ConvertKeyPairToPKCS12CompleteAltern(t *testing.T) {

	var privateKey = `-----BEGIN PRIVATE KEY-----
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
hjDR4C6EYopn1fHxRZzn38kDP+Prng==
-----END PRIVATE KEY-----
`
	var certificate = `-----BEGIN CERTIFICATE-----
MIIFhDCCA2wCCQDN50se7x+gRDANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMC
UEUxDzANBgNVBAgMBnNhbXBsZTEPMA0GA1UEBwwGc2FtcGxlMQ8wDQYDVQQKDAZz
YW1wbGUxDjAMBgNVBAsMBXNhbXBsMQ8wDQYDVQQDDAZzYW1wbGUxIDAeBgkqhkiG
9w0BCQEWEXNhbXBsZUBzYW1wbGUuY29tMB4XDTE5MTAyODE0NDAyNFoXDTIwMTAy
NzE0NDAyNFowgYMxCzAJBgNVBAYTAlBFMQ8wDQYDVQQIDAZzYW1wbGUxDzANBgNV
BAcMBnNhbXBsZTEPMA0GA1UECgwGc2FtcGxlMQ4wDAYDVQQLDAVzYW1wbDEPMA0G
A1UEAwwGc2FtcGxlMSAwHgYJKoZIhvcNAQkBFhFzYW1wbGVAc2FtcGxlLmNvbTCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALdgGvv1xSTJgFbu3RuRqDr5
rPQA84jEYLZxjd0W3o5Nt7MUuJ8jiJ4ME7T9baeaUR/KXzpmDYdmLqiubHmJVWzy
Tr467JPrT4qxDBiFbDBekIOCeOLm7B9NMwBQEOOUo4Or9kXMxSMlNDfrWNtCBOfg
B0sZsnQvm95r7ATNn2FjjuBW8RsKL/ki6djPqDXY7w9kip/n7n1W0kqlb2bQVo31
BHLAzX6w8tVHvBvPoHFMPlbw5lunj6hcptnKHeg5akjhLBNQ/HlL/pj8ym57raeJ
+v5+HZykMAcrrB9viEJJy0hIpmnawzraS1QdCppknAA+wXJT1ZQvhdlfeeeVCCId
NuhwZkRw999ek4nX0J63eGV4QJ7IgiNufQ8/lj06tsLWK42wpG3Mr4EN187avXX0
GRmwMf9pSsEztwwW752ivWTCL7pR61/XysMoOcLV7WI316JPOWXmp849hk2S/5qX
/sVzKz0cMIQONBS9VStvoTMIS0Yfdg97vqhja+aVB2BrwMZxLi6aW0i+3oZ5Foiq
LuiI0FimQEch3rr2UGFInvcDfRMyWPRMf7ncEk0hYjiIK4ge84poPGi55nkqkYao
W8j7CLxs4oCVd3/sF04l5kLFlGGnSn4TooYMLjKqiJM8YKj5ne+cahXBX/mr1gsy
rVuTXP1DbCvYPmAL0SE/AgMBAAEwDQYJKoZIhvcNAQELBQADggIBAGinKrqx0VqC
B1WFaJkZFcdoxrpv7V5ISbDTabOUQ2NeYHRiHfRFfu/1T5PDo0sicWae6Fq89IZF
dZzTLe3ieOHqmNGGhPUgZIT7t+RUYvOlR1YMGXAPj4X7nJffjwOe6b8sXw3wsqSp
+ZYJ3H/4K26led/sFx+h7B36BuW8suVPmPYnvz53Og9GG+y8ndhmPpAYoThFO3pr
3qngySLsFITCJ51pmAtHM+v3vJgvg/ypFbbD4yVW2XkOu+8YCg93cpa3GPgmJ5ON
IgAtrdOrhwBOM8YANePuGbln1yTKTcgwYm7fdbBZ8Gpm6+FlglK97R/duTR6yJnc
EGr3S815l+LUHlmgzJLWfFPHA2IZKu7KWCASA3mVMhLofoXnSzitf1qXgWEmYc/L
xTg/jaap9zG+Wjl8lxLe/QgisibVRYM8o1a6GCI3HIPEbUCmKGEt2rzqKyBuFrWA
BOkgsG2+lxG9eZ1FtRoZ2v2zoQtuxhwrekd+ciQ1W/EIjyZfFxMO2v7ppkIxcac/
hP19r+5IgwMO2vc91mqSxNZ8t1j8qTodAj2T5lmDKeyBrjSJFNcj04GrEzcdv7sL
FkwuyTBQpYJGurqXP3rp/e/S4ZGxrC1qY2mWPRtJ+VtPFqunRTPEiPlTaxUVebEY
0rcM3Y90ulmTAYJaZGJy3DbZw+hu6oCs
-----END CERTIFICATE-----
`

	instance := NewFastRSA()
	pkcs12, err := instance.ConvertKeyPairToPKCS12(privateKey, certificate, password)
	if err != nil {
		t.Fatal(err)
	}

	output, err := instance.ConvertPKCS12ToKeyPair(pkcs12, password)
	if err != nil {
		t.Fatal(err)
	}

	privateKeyConverted, err := instance.ConvertPrivateKeyToPKCS1(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, privateKeyConverted, output.PrivateKey)
	assert.Equal(t, certificate, output.Certificate)

	encoded, _ := json.MarshalIndent(output, "", " ")
	t.Log("output:", string(encoded))
}
