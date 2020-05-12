package rsa

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
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

// https://github.com/jerson/flutter-rsa/issues/8
func TestFastRSA_ConvertJWKCustomKotlin(t *testing.T) {

	jwkPrivateKey := `{
    "kty": "RSA",
    "e": "AQAB",
    "n": "ovFF6EbOtXeg7VnojIgtChgxfU6GZ16JjVj5JFHh6NGHJnq4p059BnMphcDx1mqb3yxM73FxhEszSFLcJiPzway6eIDiXuYiT-Sf_0Wl6_wDLvEmlz43psp7WYJumwpaSyiI_1FWmOVQnTnoAIKaOYKVqzUlteiECQj7XjJl0MZH16RlEfVqVpJ_8Ier4_QXIJ8Y3pe2KF3Lg9UANFU97nuvEM94CSzX-0WIju6Lykt3DBb2YtFFg4bJjOFv3T38nCZmDh8lYjm25_1qILalsB0XRoDxQy9FLxWb4zd09JsDhL0EYAQ_hNfOnQFVOBtYEHVYMCHYH6GoTcNgxmUkZPk4AfpAqZmjDzKfVJrw4Fr68pPTEQOQEzBcIWp61P21BSkhqO4QuFinkQsSH6NdTB_3FpbhYf34Hjf-iH7hdpdWo4aoRLb8eZeZcqBRZoRmlhQnOD-PVxQR_vb9rjXSjGkCWwRbsurVLWdBh_FQn0S9Q6EHqiV8nbW-R0Rk2E76JwgMFkqGUtZj8DeEqXJ2jlAvuzp56fXeAViPEtvUj1HheO8O3LxdVYCiapWWKq4qQVoRzdiyvydYSmbztgFUhekvmjNkxLNKOh71i3hFtoXycegqZ6izrUGoF2oD24lsTKsV5lV5pwfmUjVvxtHZm54bJIMfUDYbOV6yeDjYBb8",
    "d": "EePSrJeFn4f0a8rozPEwnMCeQmdKO3Q2PwYrSJES8Ch9IbzspDXqZThksTJHeya2WXD4O3vlnkRRa5npYOimnTeVO6DO-eNjlgkAhhsEBh5jzRYeChIDMzVdCK1Y7n3a_xCCxiGMk_nteW2_qrqsKy9KtoL90nSmdoV9b9CxvBPhFGyQykF7POkV0fdbaIpGtcayCNJ4ZgMyUpWi0ZwgUhxTUtGsmLlLN2Phg-vt_jZ96h5lS-E1NCUq4ORpj018fDp9DwTdamTyz5LTwaa8F1OCWDPVCW7Ztjs1o-NVXHvejYbhQZeFz9SP804PqLrb1ubDWXmFzKdHns4aRH4bWivh9L8HwSJUl5UEXprJUpYilT0tb3VauI7Cih2LBfhU3fUIDJFYm_j9etgNcPlqt64T7_TI8elgj7-sciXa1XEqIje9Mn8spxT6lpn4nhxJ9qelERCJwiWbuPnW2VsJHeqXZTly52KQEP_UBC4z8a0tDm7HIQw7WQ-OAuNUOu8ongOHaOexkqKYIcF3f812sOIVEJufoBXUUTIvJk-buH0ytgtTjkrO64zZeIvFHa1MFU-6UXh8jipSZ617znNR2Pc1-l3s7pACdbXvy2-5VWE3psRr1L5HM4KNwm6Rs5BXXqBSifzfiJ5qNGqKabfXvPXI8wYyl3mhUQtHW6sUUl0",
    "p": "0q_DP_FzSi8JEd-NNXoIaeL5MOxmNiXmDHGNxP3noKPyr-N6h3CrK5G59Rj2vWAJMhKToz1eSQ1p0-X0Ku2DvdT5LQOGIXVPtojw0OcOI8G8SoqMGAGehaLsnV3vexwtwjLfIM99XccKAxWMA1SMuL48nuBpMUhO0MlagbrL5vfpKB9kL7XCQqspAnN_vBmQZGWYczQmBgfC6v6xGQV3xHJmL--dn-qF2XU9pKuqd0J-cKYcdLPrccdJtGLid4nrSOTDfEbr77IUI5VGWV8CFJ-n8Vki-GwUxUkJpIoRyp5DxnYtSJb7cV-xOf7kBTCEUFn5B8fb2q-d8011cgnp5Q",
    "q": "xfzB-Yf4fa2y2q4ubJCJA5H-IG9-mr7fVRTUbj-gTqVL-I7MCDIImdAPbA-3EoIR5H70GVbAFGQJyYDq6eDeTbNs1zfnU0JPurASE3fKbOpoRdLwXwaSdRJRP9qnqUe-BzuloIzWc-dI-6TJxmHUSA1X9CtHvIdfNdKPCVFKUMrb1bv5arAI8tRbNRfy3tnbiw4wfKhYEQ1e6RPpxAR5F4We9RJ81-sIlfAy7WfliwmcGmgcPNdUinGR299CiVYKf5ktoqGFQ9n6K-v4gNZV23f33-tuD8pMVxyc3xG34j4frH57bsbm7v8Qz-92ZxHWzOUgxIVhGgSaa4E51d9m0w",
    "dp": "yArepo4I230BbZkHKKlv56n81PkAq5UccuA2rb4u-ZXxThP9OTA_NiUtnYxQassOsB53U91m8pHr06hZR5ExL0NSO-1Go-oQ_83SaWeZQ1YmA9i83-ZZr6VcaKbSReAhimxm825PKIVd-kOxJ1BWNOtb_7Yv6v0u6IrmhproE6t8E_6KT8qSYl7Fl3A27lCPiuPz9h6jo8Imzp15ZbqNV1cPs6Ad18MDx8_L8diVCJt4FlmCV0Sl3uhMERx6zumDHzkma4-jYXmCKa8Ilr7g6NgWy8_Ipnto1VFd-H6oGexficaXhH7my2UCj4B23H6OgwSKsVqQY3mvzV3Uj6zeCQ",
    "dq": "a0_ey6OZWnWFleYHH60PtrGw7l_AXZvLbVBG_CLcfwQ1M1oi2OZVpxkQ4t95uTxq-lCdegZ9QhAfBessaOwLUk5IVjbk2Un98RByG784JuS-8-mrg7YKOA5fn56idax_IWiBE46Cxnu8ITlmbHKmHw-sdpnm3hb50jB4evJmt3fcw_KI8_zKPORBM3vxljy7NJnSSh7s7QE0Sl0Svb427Drut6L3rAimtK5mzCseTcg9pkp707ZbClcYWfafF9VdB2A9TgMCOo6xfJEANsT18GkMH4B6PXDHBAhsNrRh2O0XOeWsfZStoyj5Mdt3b9JJfPFMW3h38yQ_lrmKYZQfJQ",
    "qi": "aDsPYxE-JBYsYhCYXSU7WsCrnFxNsRpFMcYXdmdryYIdQUpeemChDGzVJXLnJhE4cAS9TtLcNg82xZSKZvHrnkbFpRfSJxzEnvIXW4V0LHkxkxbmM0e9B7UrpYm6LKtvEY6I7L8wHFpHdOwV6NjY925oULEV156X0r55V7N0XF-jy3rbm71DCWRh6IDRghhCZQ3aNgJxE-OtnABqasaY6CQnTDRXLkGE0kq9GCx85-92fQLHMzvrMhr9m_2MHYJ_gZehL4j95CQzhD3Zh602D0YYYwRSsU4h5HGjlmN52pe-rfTLgwCJq5295s7qUP8TTMzbZAOM_hehksHpAaFghA"
}`

	stringToSignBase64 := `ovFF6EbOtXeg7VnojIgtChgxfU6GZ16JjVj5JFHh6NGHJnq4p059BnMphcDx1mqb3yxM73FxhEszSFLcJiPzway6eIDiXuYiT-Sf_0Wl6_wDLvEmlz43psp7WYJumwpaSyiI_1FWmOVQnTnoAIKaOYKVqzUlteiECQj7XjJl0MZH16RlEfVqVpJ_8Ier4_QXIJ8Y3pe2KF3Lg9UANFU97nuvEM94CSzX-0WIju6Lykt3DBb2YtFFg4bJjOFv3T38nCZmDh8lYjm25_1qILalsB0XRoDxQy9FLxWb4zd09JsDhL0EYAQ_hNfOnQFVOBtYEHVYMCHYH6GoTcNgxmUkZPk4AfpAqZmjDzKfVJrw4Fr68pPTEQOQEzBcIWp61P21BSkhqO4QuFinkQsSH6NdTB_3FpbhYf34Hjf-iH7hdpdWo4aoRLb8eZeZcqBRZoRmlhQnOD-PVxQR_vb9rjXSjGkCWwRbsurVLWdBh_FQn0S9Q6EHqiV8nbW-R0Rk2E76JwgMFkqGUtZj8DeEqXJ2jlAvuzp56fXeAViPEtvUj1HheO8O3LxdVYCiapWWKq4qQVoRzdiyvydYSmbztgFUhekvmjNkxLNKOh71i3hFtoXycegqZ6izrUGoF2oD24lsTKsV5lV5pwfmUjVvxtHZm54bJIMfUDYbOV6yeDjYBb8gMSBjb2x1bW4gaW4gdGhlIHBhdHRlcm4gaXMgc29saWQgY29sb3IgYW5kIHRoZXJlIGFyZSAxNyBjb2x1bW5zIGluIHRoZSBpbWFnZS4gIElmIHlvdSBleHRlbmQgdGhpcyBvdXQgdG8gMTAwMCBjb2x1bW5zLCB0aGlzIHBhdHRlcm4gd2lsbCByZXBlYXQgNTggdGltZXMgKyBzb21lIGV4dHJhIGNvbHVtbnMuICBTbywgdGhlcmUgd2lsbCA1OCArMSBjb2x1bW5zIHNpbmNlIHRoZSBmaXJzdCBjb2x1bW4gaXMgdGhlIG9ubHkg`
	stringToSignBytes, err := base64.URLEncoding.DecodeString(stringToSignBase64)
	if err != nil {
		t.Fatal(err)
	}

	instance := NewFastRSA()
	privateKey, err := instance.ConvertJWKToPrivateKey(jwkPrivateKey, "")
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := instance.ConvertPrivateKeyToPublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	signed, err := instance.SignPSSBytes(stringToSignBytes, "sha256", "equalsHash", privateKey)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := instance.VerifyPSSBytes(signed, stringToSignBytes, "sha256", "equalsHash", publicKey)
	if err != nil {
		t.Fatal(fmt.Errorf("instance.VerifyPSSBytes with signed: %w", err))
	}

	assert.True(t, verified)

	//kotlinStringToVerify := `fpoY3ZYBwT45E3vNoN7HS96OdOSIiXt4lda0kFSq97i4PXx0-TMCki-wKG3LJUXoKX3f8wwU0LM4J76HEYL2pVpp9p9XpClvFeL6rbcz8Z4yAhvkqm9fNXla0lRAPEJhTA5RW71KskotVb9qJRjXqnlF0oiOfQE-RqyipvEsfSudzE1Y1C-mhxZXxuKYv4ZXmjyohbJpnINTEa3azgWXPgIkTCHw_1vpeadz0wupF1ortMOtQj1pXzen3X9B0BMJ3G_CScfmGY7O8q1EmL8fdtslNfQgOWyMUJhb5bfS2nxshzoH0RyxqNJBOG5JPLutIsNQNWdRRlhvXb9oWwvspTTU9zVYpFvL75xnD5iKL3Tj1nlgn_s7Goo-VgpqeyNklqe-dCuhmkegCp-TjB7JV-UV6st9986NrBaD4UJCYlMQq7KnyOsep_lrSG-UVS-pbIeMku-25afIob5l21GqmnLbHKu5SeLqpNZbw-9wHV0-EqGkD8dOG8ZUmMfFMzZASQpXREC8IdEiLhr-HThuc0I3wFgb1roxrrDwTYABchzq4wLUyXQjXb1iDQ5a1Gf5LGdFG3rik4jl2_q011JheI9HhWKBuYC5nERnSzhi0_quYByjKkwxHTSNm6tDeZGqQFFeuSKCxbOgGENZBrzyFguTNh6jgqg6WaC3uoy9swQ=`
	//kotlinStringToVerifyBytes, err := base64.URLEncoding.DecodeString(kotlinStringToVerify)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//verifiedKotlin, err := instance.VerifyPSSBytes(signed, kotlinStringToVerifyBytes, "sha256", "equalsHash", publicKey)
	//if err != nil {
	//	t.Fatal(fmt.Errorf("instance.VerifyPSSBytes verifiedKotlin with signed: %w", err))
	//}
	//assert.True(t, verifiedKotlin)

	t.Log("output:", signed)
}
