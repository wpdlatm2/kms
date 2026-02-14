package kmip

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// KeyGenerator는 다양한 타입의 키를 생성하는 인터페이스
type KeyGenerator interface {
	GenerateSymmetricKey(algorithm int32, length int32) ([]byte, error)
	GenerateRSAKeyPair(length int32) (publicKey, privateKey []byte, err error)
	GenerateECDSAKeyPair(curve string) (publicKey, privateKey []byte, err error)
}

// DefaultKeyGenerator는 기본 키 생성기
type DefaultKeyGenerator struct{}

// NewKeyGenerator는 새로운 키 생성기를 생성
func NewKeyGenerator() KeyGenerator {
	return &DefaultKeyGenerator{}
}

// GenerateSymmetricKey는 대칭 키를 생성
func (g *DefaultKeyGenerator) GenerateSymmetricKey(algorithm int32, length int32) ([]byte, error) {
	// 알고리즘별 특수 처리
	switch algorithm {
	case CryptoAlgorithmSEED:
		return GenerateSEEDKey(length)
	case CryptoAlgorithmARIA:
		return GenerateARIAKey(length)
	}
	
	// 길이를 바이트로 변환 (비트 -> 바이트)
	keyBytes := length / 8
	
	keyMaterial := make([]byte, keyBytes)
	if _, err := rand.Read(keyMaterial); err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %v", err)
	}
	
	return keyMaterial, nil
}

// GenerateRSAKeyPair는 RSA 키 쌍을 생성
func (g *DefaultKeyGenerator) GenerateRSAKeyPair(length int32) (publicKey, privateKey []byte, err error) {
	// RSA 키 길이 검증 (512 ~ 8192 비트)
	if length < 512 || length > 8192 {
		return nil, nil, fmt.Errorf("RSA key length must be between 512 and 8192 bits")
	}
	
	// RSA 키 생성
	privKey, err := rsa.GenerateKey(rand.Reader, int(length))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key pair: %v", err)
	}
	
	// 개인 키를 PKCS#8 형식으로 인코딩
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	
	// 공개 키를 PKIX 형식으로 인코딩
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %v", err)
	}
	
	return publicKeyBytes, privateKeyBytes, nil
}

// GenerateECDSAKeyPair는 ECDSA 키 쌍을 생성
func (g *DefaultKeyGenerator) GenerateECDSAKeyPair(curveName string) (publicKey, privateKey []byte, err error) {
	// 곡선 선택
	var curve elliptic.Curve
	switch curveName {
	case "P-192", "secp192r1", "prime192v1":
		curve = elliptic.P192()
	case "P-224", "secp224r1":
		curve = elliptic.P224()
	case "P-256", "secp256r1", "prime256v1":
		curve = elliptic.P256()
	case "P-384", "secp384r1":
		curve = elliptic.P384()
	case "P-521", "secp521r1":
		curve = elliptic.P521()
	default:
		// 기본값: P-256
		curve = elliptic.P256()
	}
	
	// ECDSA 키 생성
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key pair: %v", err)
	}
	
	// 개인 키를 PKCS#8 형식으로 인코딩
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	
	// 공개 키를 PKIX 형식으로 인코딩
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %v", err)
	}
	
	return publicKeyBytes, privateKeyBytes, nil
}

// GetCurveName은 비트 길이에서 곡선 이름을 반환
func GetCurveName(length int32) string {
	switch length {
	case 192:
		return "P-192"
	case 224:
		return "P-224"
	case 256:
		return "P-256"
	case 384:
		return "P-384"
	case 521:
		return "P-521"
	default:
		return "P-256" // 기본값
	}
}

// GetAlgorithmFromString은 문자열에서 알고리즘 상수를 반환
func GetAlgorithmFromString(algo string) int32 {
	switch algo {
	case "AES":
		return CryptoAlgorithmAES
	case "DES":
		return CryptoAlgorithmDES
	case "3DES", "DES3":
		return CryptoAlgorithmDES3
	case "RSA":
		return CryptoAlgorithmRSA
	case "DSA":
		return CryptoAlgorithmDSA
	case "ECDSA":
		return CryptoAlgorithmECDSA
	case "HMAC-SHA1":
		return CryptoAlgorithmHMACSHA1
	case "HMAC-SHA256":
		return CryptoAlgorithmHMACSHA256
	case "HMAC-SHA384":
		return CryptoAlgorithmHMACSHA384
	case "HMAC-SHA512":
		return CryptoAlgorithmHMACSHA512
	case "RC4":
		return CryptoAlgorithmRC4
	case "ECDH":
		return CryptoAlgorithmECDH
	case "ARIA":
		return CryptoAlgorithmARIA
	case "SEED":
		return CryptoAlgorithmSEED
	default:
		return CryptoAlgorithmAES // 기본값
	}
}

// GetAlgorithmString은 알고리즘 상수에서 문자열을 반환
func GetAlgorithmString(algo int32) string {
	switch algo {
	case CryptoAlgorithmAES:
		return "AES"
	case CryptoAlgorithmDES:
		return "DES"
	case CryptoAlgorithmDES3:
		return "3DES"
	case CryptoAlgorithmRSA:
		return "RSA"
	case CryptoAlgorithmDSA:
		return "DSA"
	case CryptoAlgorithmECDSA:
		return "ECDSA"
	case CryptoAlgorithmHMACSHA1:
		return "HMAC-SHA1"
	case CryptoAlgorithmHMACSHA256:
		return "HMAC-SHA256"
	case CryptoAlgorithmHMACSHA384:
		return "HMAC-SHA384"
	case CryptoAlgorithmHMACSHA512:
		return "HMAC-SHA512"
	case CryptoAlgorithmRC4:
		return "RC4"
	case CryptoAlgorithmECDH:
		return "ECDH"
	case CryptoAlgorithmARIA:
		return "ARIA"
	case CryptoAlgorithmSEED:
		return "SEED"
	default:
		return "Unknown"
	}
}
