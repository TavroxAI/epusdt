package sign

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/GMWalletApp/epusdt/util/json"
	"github.com/gookit/goutil/strutil"
)

// Get 获取签名
func Get(data interface{}, bizKey string) (string, error) {
	signStr, err := canonicalParams(data)
	if err != nil {
		return "", err
	}
	return strutil.Md5(signStr + bizKey), nil
}

// GetHMACSHA256 returns the lowercase hexadecimal HMAC-SHA256 signature of
// the canonical parameter string, using bizKey as the HMAC key.
func GetHMACSHA256(data interface{}, bizKey string) (string, error) {
	signStr, err := canonicalParams(data)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, []byte(bizKey))
	_, _ = mac.Write([]byte(signStr))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func canonicalParams(data interface{}) (string, error) {
	switch v := reflect.ValueOf(data); v.Kind() {
	case reflect.Map:
		return MapToParams(data.(map[string]interface{}))
	case reflect.Struct:
		return Struct2map(v.Interface())
	default:
		return "", errors.New("type err")
	}
}

// SignEd25519 signs the canonical parameter string of data with priv and returns
// the lower-case hexadecimal signature. It shares canonicalParams with
// GetHMACSHA256, so an HMAC-signed body and an Ed25519-signed body are always
// computed over the same bytes.
func SignEd25519(data interface{}, priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("ed25519 private key has an invalid length")
	}
	signStr, err := canonicalParams(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(priv, []byte(signStr))), nil
}

// Canonical returns the signature payload for data. Callers use it for the
// pre-send self-check: re-sign the exact bytes that go on the wire and compare.
func Canonical(data interface{}) (string, error) {
	return canonicalParams(data)
}

// KeyIDFor returns the key id of a public key: the first 8 lower-case hex
// characters. Merchant installations use it to tell key rotations apart.
func KeyIDFor(pub ed25519.PublicKey) string {
	encoded := hex.EncodeToString(pub)
	if len(encoded) > 8 {
		return encoded[:8]
	}
	return encoded
}

// PrivateKeyFromSeedHex parses a 64-character hex Ed25519 seed (the raw 32-byte
// seed, not a PEM file). Whitespace and upper case are tolerated.
func PrivateKeyFromSeedHex(raw string) (ed25519.PrivateKey, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("ed25519 signing seed is empty")
	}
	seed, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("ed25519 signing seed is not hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519 signing seed must be %d bytes (%d hex characters), got %d bytes", ed25519.SeedSize, ed25519.SeedSize*2, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PublicKeyHex returns the lower-case hex encoding of a private key's public
// half, which is what the merchant pastes into its trust store.
func PublicKeyHex(priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("ed25519 private key has an invalid length")
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("ed25519 public key is unavailable")
	}
	return hex.EncodeToString(pub), nil
}

func Struct2map(content interface{}) (string, error) {
	var params map[string]interface{}
	marshal, err := json.Cjson.Marshal(content)
	if err != nil {
		return "", err
	}
	if err = json.Cjson.Unmarshal(marshal, &params); err != nil {
		return "", err
	}
	paramsUrl, err := MapToParams(params)
	return paramsUrl, err
}

func MapToParams(params map[string]interface{}) (string, error) {
	var tempArr []string
	temString := ""
	for k, v := range params {
		if k == "signature" {
			continue
		}
		if v == nil {
			continue
		}
		fv := ""
		switch v.(type) {
		case float64:
			ft := v.(float64)
			fv = strconv.FormatFloat(ft, 'f', -1, 64)
		case float32:
			ft := v.(float32)
			fv = strconv.FormatFloat(float64(ft), 'f', -1, 64)
		case int:
			it := v.(int)
			fv = strconv.Itoa(it)
		case uint:
			it := v.(uint)
			fv = strconv.Itoa(int(it))
		case int8:
			it := v.(int8)
			fv = strconv.Itoa(int(it))
		case uint8:
			it := v.(uint8)
			fv = strconv.Itoa(int(it))
		case int16:
			it := v.(int16)
			fv = strconv.Itoa(int(it))
		case uint16:
			it := v.(uint16)
			fv = strconv.Itoa(int(it))
		case int32:
			it := v.(int32)
			fv = strconv.Itoa(int(it))
		case uint32:
			it := v.(uint32)
			fv = strconv.Itoa(int(it))
		case int64:
			it := v.(int64)
			fv = strconv.FormatInt(it, 10)
		case uint64:
			it := v.(uint64)
			fv = strconv.FormatUint(it, 10)
		case string:
			fv = v.(string)
		case bool:
			// bool participates as "true"/"false". CheckoutCounterResponse
			// carries is_selected, so without this branch every signed snapshot
			// would fail with "signature marshal error". Nested objects and
			// arrays still fall through to the error on purpose.
			fv = strconv.FormatBool(v.(bool))
		case []byte:
			fv = string(v.([]byte))
		default:
			return "", errors.New("signature marshal error")
		}
		// 空值不参与签名
		if fv == "" {
			continue
		}
		tempArr = append(tempArr, k+"="+fv)
	}
	sort.Strings(tempArr)
	for n, v := range tempArr {
		if n+1 < len(tempArr) {
			temString = temString + v + "&"
		} else {
			temString = temString + v
		}
	}
	return temString, nil
}
