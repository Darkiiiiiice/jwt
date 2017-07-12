package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	JwtType      = "JWT"
	JwtAlgorithm = "HS256"
	JwtSecret    = "Secret"
)

type TokenHeader struct {
	Type        string `json:"typ"` //签名类型
	Algorithm   string `json:"alg"` //签名算法
	ContentType string `json:"cty"` //
}

type TokenPlayload struct {
	Issuer         string `json:"iss"`  //JWT签发者
	Subject        string `json:"sub"`  //jwt面向用户
	Audience       string `json:"aud"`  //jwt接收用
	ExpirationTime int64  `json:"exp"`  //jwt截止时间戳
	NotBefore      int64  `json:"nbf"`  //jwt在时间
	IssuedAt       int64  `json:"iat"`  //签发时间
	JWTID          string `json:"jti"`  //jwt唯一标识
	Data           string `json:"data"` //jwt附加数据
}

type Token struct {
	Header    *TokenHeader
	Playload  *TokenPlayload
	Signature string
}

func NewToken() *Token {
	return &Token{
		Header: &TokenHeader{
			Type:      JwtType,
			Algorithm: JwtAlgorithm,
		},
		Playload: &TokenPlayload{},
	}
}

func (t *Token) Encode() string {
	header := t.Header
	bytesHeader, err := json.Marshal(header)
	if err != nil {
		fmt.Errorf("header json error:%v\n", err.Error())
		return ""
	}
	fmt.Println(string(bytesHeader))

	strHeader := base64.StdEncoding.EncodeToString(bytesHeader)

	playload := t.Playload
	bytesPlayload, err := json.Marshal(playload)
	if err != nil {
		fmt.Errorf("playload json error:%v\n", err.Error())
		return ""
	}
	fmt.Println(string(bytesPlayload))

	strPlayload := base64.StdEncoding.EncodeToString(bytesPlayload)

	uSignature := strHeader + "." + strPlayload

	signature := t.sha256Encode(uSignature, JwtSecret)
	fmt.Println(signature)
	return uSignature + "." + signature
}

func (t *Token) Decode(jwt string, secret string) {
	if ok, err := t.validate(jwt, secret); !ok && err != nil {
		return
	}

	strs := strings.Split(jwt, ".")
	header, err := base64.StdEncoding.DecodeString(strs[0])
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	playload, err := base64.StdEncoding.DecodeString(strs[1])
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	tHeader := new(TokenHeader)
	err = json.Unmarshal(header, &tHeader)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	tPlayload := new(TokenPlayload)
	err = json.Unmarshal(playload, &tPlayload)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	t.Header = tHeader
	t.Playload = tPlayload
	t.Signature = strs[2]
}

func (t *Token) validate(message string, secret string) (bool, error) {
	strs := strings.Split(message, ".")
	if len(strs) != 3 {
		return false, errors.New("Incorrect message")
	}
	usign := strs[0] + "." + strs[1]
	sign := t.sha256Encode(usign, secret)
	if sign != strs[2] {
		return false, errors.New("Cann't passed validate")
	}
	return true, nil
}

func (t *Token) sha256Encode(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
