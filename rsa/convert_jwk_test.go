package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var jwkPrivateKey = `{
          "d": "K2OnHuUpb6nqHyfH06UkbEf1n4q2FS96PtEhoyWtJXjINax6ftU2l0b-Rr4MezLtbRtCaxwIqXgJJEqZSiyvtOaksShaICn2mTeJSCgR0GQfx65QkkfXqRRoM_O9-0uJYTeIPz3Ti5xa_bxHOyIk7QS6VQ_QhONa-0cIAp7wzmdzQCvyQtanQUj8khuYjp00-6xrjKiharDnc1gvwuEbCd3m3ow2U3rlCog9v0riiMxkl8fKifdc65Z4uGG1r-Qd_P6iojNwefb8WBDAiWHkVhc095C5yv2ii5_Oy2VllWHGouTl03g656sNVerFPoD91KUEutuRVs3j2upXeu9ti9ZYkF35cEFBjndf0s4afVe4B4vJv-WgNQSOZKwhbw9pEUyrGWdM1ETlEmItsR1ISSlb_Uu2L0I-Ds22VHjH2NTJpnr58kOxL0qer9xTUhqVwiAK6ULgYbPBsgBLN_qnwze75ASmTVvzzLmrREmkWeaM6oYYLExBhNW2mlXHon0o8KwxCPirA0Vjx4wa5K206FYnXQ5aJkRbThNfnOuOwpAcAB30xtOFk_rqiNTpUw855ce1Ant4LNR6jfGE6lqefAxxiq623cfuA1n8lJiRrTCL8k6sYonyIvabqCGv1gz-YlV09z6Qm0tzOZ_gOQhLo2WqJomFR5UVKWL9xyOcouk",
          "dp": "Eptxr2lAgpv3vZVcXePJ6lql3ADF08mZR48Rrj6OruX1fFvknfXX2uzFVU4OlFbjYUI06h8y94bGExH7jgF65yEJSmOx_p8uGdTcGdZFQTUFx-3PIxIrSf3GXqwM4TK4CsHoMjxygUHN-_uW2SoTBhsIYHlih-oJQS3lbar6dKvGGGM8TBTPlVodGBQY9YCfSldzT_A0ARf1d61ev7Ym6zTg7bEuyxOXO2gq133HPTap29QoxU7p3sBySY1Fj9kQclkQH-TaOUmtAigjDAhxhyr21X_oa2BF-yXGKev_bcctSHW9wEVAzvo4wgTYI2jkYYkL1f3i8yCZmNdhgnqhRw",
          "dq": "D7xVOvBI4VDS-iBZoXaJ04HJIZ_Pcm2pKncTT8CLpgRkIYbRBtDok4COIp1t7M5Y7Z1JD8BLkCJJMKrRkK1NpE6Fv4IoxuW-RKwyuTw0Ttpls5WVM2T64TSOLh8bxEKe2G24LxC_lALMwQ4mgYI9KuRVMjSL3AHS0ZF01yOEiCqcTaZZD8NlkBbYyjqLv33TyU2LhmkcEUZY4mYPULRrlMhIn1ENgyMeDfX75OOty-JNv2qOQJF-8OSgBRQFohnxu7eojss5PbEYYITJ7Kvbl-3Ya9_8iwdh6giNLTtE3o63G9g0jSFXNUaiw4V6HtE9Vz_ABJhGJ0vHWch4pib1eQ",
          "e": "AQAB",
          "kty": "RSA",
          "n": "t2Aa-_XFJMmAVu7dG5GoOvms9ADziMRgtnGN3Rbejk23sxS4nyOIngwTtP1tp5pRH8pfOmYNh2YuqK5seYlVbPJOvjrsk-tPirEMGIVsMF6Qg4J44ubsH00zAFAQ45Sjg6v2RczFIyU0N-tY20IE5-AHSxmydC-b3mvsBM2fYWOO4FbxGwov-SLp2M-oNdjvD2SKn-fufVbSSqVvZtBWjfUEcsDNfrDy1Ue8G8-gcUw-VvDmW6ePqFym2cod6DlqSOEsE1D8eUv-mPzKbnutp4n6_n4dnKQwByusH2-IQknLSEimadrDOtpLVB0KmmScAD7BclPVlC-F2V9555UIIh026HBmRHD3316TidfQnrd4ZXhAnsiCI259Dz-WPTq2wtYrjbCkbcyvgQ3Xztq9dfQZGbAx_2lKwTO3DBbvnaK9ZMIvulHrX9fKwyg5wtXtYjfXok85Zeanzj2GTZL_mpf-xXMrPRwwhA40FL1VK2-hMwhLRh92D3u-qGNr5pUHYGvAxnEuLppbSL7ehnkWiKou6IjQWKZARyHeuvZQYUie9wN9EzJY9Ex_udwSTSFiOIgriB7zimg8aLnmeSqRhqhbyPsIvGzigJV3f-wXTiXmQsWUYadKfhOihgwuMqqIkzxgqPmd75xqFcFf-avWCzKtW5Nc_UNsK9g-YAvRIT8",
          "p": "267Ym9RG1KALgj3LqvdGVhTyhHrB_1PwAR92oSWJXCB8ElOErJgWinl8ebkQwlDgsVmdak6K8LkZOCDFwK6NPageaUlMhiovXRBeY6Gxe780NACCpXBQQJ0vqQqKUZwqfxktnfuy-DhpyNLL973Ikx5SV_tXozyy5qRkVQ9c6UZF1G8VUi_a1ig8PR1sxgK2HhpdCZ3EMumRBhR-91NFj-yjAbYkQrQ-Ht8Jh9h27_4czNst9HS7f-Y40SuKW-VD54jyEgfwDLlQpv_TLmrJ4si0by2bVoC7Ni1ZIbg18o_Ahm8-84xi4yGzLcbSN3sryRfn-XA_gT9aaUk0hZBKmw",
          "q": "1bCxxYR_0dWUJ6SJKsOYkA1mxZff3eWq67_NcCG0mTLumLd2YRIcB7LaFMVcGbBPkSUrBbHhQY6NQk7WtBWNt928NXcoDYBTuojTn5yRS8l_hYgoXeaolwuIC70MzbuhGnJmUHeZji7u6VgjoPsn2DBh85LVstqzDRBcHpLQWRJg-13StGF2ej1eKSDjJRwTeYvEX7qI_DPjLrsGZ_TE-HXWLbVa7lDnwxrwjpCjyGnBEpUKqzgYvXURYiMneQdPw2OijpN4QDQYRkt0ddtOZAPWgNE8UGnuChp7KUseVUajusqoHt32YNqNN3-3PItpzLWXMwu1tnmCeEyD58pMLQ",
          "qi": "xpSax2FQIxwKm8um4CpHxfP4wpO3_fcDZ-Jl4pDzSv6cCz_ZM3CauoTeVnICkH_XqSlVu50d2v9dRf2rEQOQ6ul0bznw5HM-Se9vULdv6Wq_dio_wQKDk0FyeeD7RtkUlHJpshoUlm3Qmmj8asIGUl9qiKgwtU-1a_WuRN0MsggqiredgqG8XLmefct_7WLczDfdfQ-2nWG517wkgnyVuPwx-k7rRjIhiWGNybtDEgxIBQuCgy8oSCj1nIzl-G0TqRTbyh7A9jI6rUU0oMocVnWXNwYLNcfi7Crn-ecOhmK4jAVQod3vo3WfhjDR4C6EYopn1fHxRZzn38kDP-Prng"
        }`

var jwkPublicKey = `{
          "e": "AQAB",
          "kty": "RSA",
          "n": "t2Aa-_XFJMmAVu7dG5GoOvms9ADziMRgtnGN3Rbejk23sxS4nyOIngwTtP1tp5pRH8pfOmYNh2YuqK5seYlVbPJOvjrsk-tPirEMGIVsMF6Qg4J44ubsH00zAFAQ45Sjg6v2RczFIyU0N-tY20IE5-AHSxmydC-b3mvsBM2fYWOO4FbxGwov-SLp2M-oNdjvD2SKn-fufVbSSqVvZtBWjfUEcsDNfrDy1Ue8G8-gcUw-VvDmW6ePqFym2cod6DlqSOEsE1D8eUv-mPzKbnutp4n6_n4dnKQwByusH2-IQknLSEimadrDOtpLVB0KmmScAD7BclPVlC-F2V9555UIIh026HBmRHD3316TidfQnrd4ZXhAnsiCI259Dz-WPTq2wtYrjbCkbcyvgQ3Xztq9dfQZGbAx_2lKwTO3DBbvnaK9ZMIvulHrX9fKwyg5wtXtYjfXok85Zeanzj2GTZL_mpf-xXMrPRwwhA40FL1VK2-hMwhLRh92D3u-qGNr5pUHYGvAxnEuLppbSL7ehnkWiKou6IjQWKZARyHeuvZQYUie9wN9EzJY9Ex_udwSTSFiOIgriB7zimg8aLnmeSqRhqhbyPsIvGzigJV3f-wXTiXmQsWUYadKfhOihgwuMqqIkzxgqPmd75xqFcFf-avWCzKtW5Nc_UNsK9g-YAvRIT8"
        }`

func TestFastRSA_ConvertJWKToPrivateKey(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.ConvertJWKToPrivateKey(jwkPrivateKey, "")
	if err != nil {
		t.Fatal(err)
	}

	privateKeyConverted, err := instance.ConvertPrivateKeyToPKCS1(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, privateKeyConverted, output)
	t.Log("output:", output)
}

func TestFastRSA_ConvertJWKToPublicKey(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.ConvertJWKToPublicKey(jwkPublicKey, "")
	if err != nil {
		t.Fatal(err)
	}

	publicKeyConverted, err := instance.ConvertPublicKeyToPKCS1(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, publicKeyConverted, output)
	t.Log("output:", output)
}
