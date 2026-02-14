package kmip

import (
	"encoding/binary"
	"errors"
	"io"
)

// TTLV Tag 타입
type Tag uint32

// TTLV Type 타입
type Type byte

const (
	TypeStructure   Type = 0x01
	TypeInteger     Type = 0x02
	TypeLongInteger Type = 0x03
	TypeBigInteger  Type = 0x04
	TypeEnumeration Type = 0x05
	TypeBoolean     Type = 0x06
	TypeTextString  Type = 0x07
	TypeByteString  Type = 0x08
	TypeDateTime    Type = 0x09
	TypeInterval    Type = 0x0A
)

// KMIP 주요 태그들
const (
	TagRequestMessage          Tag = 0x420078
	TagResponseMessage         Tag = 0x42007C
	TagRequestHeader           Tag = 0x420077
	TagResponseHeader          Tag = 0x42007A
	TagBatchItem               Tag = 0x42000F
	TagOperation               Tag = 0x42005C
	TagResultStatus            Tag = 0x42007F
	TagResultReason            Tag = 0x42007E
	TagResultMessage           Tag = 0x42007D
	TagProtocolVersion         Tag = 0x420069
	TagProtocolVersionMajor    Tag = 0x42006A
	TagProtocolVersionMinor    Tag = 0x42006B
	TagMaximumResponseSize     Tag = 0x420059
	TagBatchCount              Tag = 0x42000D
	TagTimeStamp               Tag = 0x420092
	TagBatchOrderOption        Tag = 0x42000E
	TagUniqueIdentifier        Tag = 0x420094
	TagObjectType              Tag = 0x420057
	TagManagedObject           Tag = 0x420053
	TagAttributes              Tag = 0x420008
	TagName                    Tag = 0x420053
	TagNameValue               Tag = 0x420055
	TagNameType                Tag = 0x420054
	TagCryptographicAlgorithm  Tag = 0x420028
	TagCryptographicLength     Tag = 0x42002A
	TagCryptographicUsageMask  Tag = 0x42002C
	TagKeyFormatType           Tag = 0x420042
	TagKeyBlock                Tag = 0x420040
	TagKeyValue                Tag = 0x420045
	TagKeyMaterial             Tag = 0x420043
	TagCryptographicParameters Tag = 0x42002B
	TagState                   Tag = 0x42008D
	TagInitialDate             Tag = 0x420093
)

// KMIP 작업 타입
const (
	OperationCreate          = 0x00000001
	OperationCreateKeyPair   = 0x00000002
	OperationRegister        = 0x00000003
	OperationRekey           = 0x00000004
	OperationDeriveKey       = 0x00000005
	OperationCertify         = 0x00000006
	OperationRecertify       = 0x00000007
	OperationLocate          = 0x00000008
	OperationCheck           = 0x00000009
	OperationGet             = 0x0000000A
	OperationGetAttributes   = 0x0000000B
	OperationGetAttributeList = 0x0000000C
	OperationAddAttribute    = 0x0000000D
	OperationModifyAttribute = 0x0000000E
	OperationDeleteAttribute = 0x0000000F
	OperationObtainLease     = 0x00000010
	OperationGetUsageAllocation = 0x00000011
	OperationActivate        = 0x00000012
	OperationRevoke          = 0x00000013
	OperationDestroy         = 0x00000014
	OperationArchive         = 0x00000015
	OperationRecover         = 0x00000016
	OperationValidate        = 0x00000017
	OperationQuery           = 0x00000018
	OperationCancel          = 0x00000019
	OperationPoll            = 0x0000001A
	OperationNotify          = 0x0000001B
	OperationPut             = 0x0000001C
	OperationReKeyKeyPair    = 0x0000001D
	OperationDiscoverVersions = 0x0000001E
	OperationEncrypt         = 0x0000001F
	OperationDecrypt         = 0x00000020
	OperationSign            = 0x00000021
	OperationSignatureVerify = 0x00000022
	OperationMAC             = 0x00000023
	OperationMACVerify       = 0x00000024
)

// Cryptographic Algorithm
const (
	CryptoAlgorithmDES        = 0x00000001
	CryptoAlgorithmDES3       = 0x00000002
	CryptoAlgorithmAES        = 0x00000003
	CryptoAlgorithmRSA        = 0x00000004
	CryptoAlgorithmDSA        = 0x00000005
	CryptoAlgorithmECDSA      = 0x00000006
	CryptoAlgorithmHMACSHA1   = 0x00000007
	CryptoAlgorithmHMACSHA224 = 0x00000008
	CryptoAlgorithmHMACSHA256 = 0x00000009
	CryptoAlgorithmHMACSHA384 = 0x0000000A
	CryptoAlgorithmHMACSHA512 = 0x0000000B
	CryptoAlgorithmRC4        = 0x0000000C
	CryptoAlgorithmECDH       = 0x0000000D
	CryptoAlgorithmARIA       = 0x0000000E // ARIA (Korean Standard)
	CryptoAlgorithmSEED       = 0x0000000F // SEED (Korean Standard)
)

// Cryptographic Usage Mask
const (
	UsageMaskSign           = 0x00000001
	UsageMaskVerify         = 0x00000002
	UsageMaskEncrypt        = 0x00000004
	UsageMaskDecrypt        = 0x00000008
	UsageMaskWrapKey        = 0x00000010
	UsageMaskUnwrapKey      = 0x00000020
	UsageMaskExport         = 0x00000040
	UsageMaskMACGenerate    = 0x00000080
	UsageMaskMACVerify      = 0x00000100
	UsageMaskDeriveKey      = 0x00000200
	UsageMaskKeyAgreement   = 0x00000800
	UsageMaskCertificateSign = 0x00001000
	UsageMaskCRLSign        = 0x00002000
	UsageMaskAuthenticate   = 0x00100000
	UsageMaskUnrestricted   = 0x00200000
)

// Result Status
const (
	ResultStatusSuccess              = 0x00000000
	ResultStatusOperationFailed      = 0x00000001
	ResultStatusOperationPending     = 0x00000002
	ResultStatusOperationUndone      = 0x00000003
)

// Object Type
const (
	ObjectTypeCertificate     = 0x00000001
	ObjectTypeSymmetricKey    = 0x00000002
	ObjectTypePublicKey       = 0x00000003
	ObjectTypePrivateKey      = 0x00000004
	ObjectTypeSplitKey        = 0x00000005
	ObjectTypeTemplate        = 0x00000006
	ObjectTypeSecretData      = 0x00000007
	ObjectTypeOpaqueObject    = 0x00000008
)

// TTLV 아이템 구조체
type TTLVItem struct {
	Tag    Tag
	Type   Type
	Length uint32
	Value  interface{}
}

// TTLV 인코더
func EncodeTTLV(w io.Writer, item *TTLVItem) error {
	// Tag (3 bytes) + Type (1 byte)
	tagBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tagBytes, uint32(item.Tag))
	tagBytes[0] = tagBytes[1] // 3바이트 태그
	tagBytes[1] = tagBytes[2]
	tagBytes[2] = tagBytes[3]
	tagBytes[3] = byte(item.Type)
	
	if _, err := w.Write(tagBytes); err != nil {
		return err
	}
	
	// Length (4 bytes)
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, item.Length)
	if _, err := w.Write(lengthBytes); err != nil {
		return err
	}
	
	// Value
	return encodeValue(w, item.Type, item.Value, item.Length)
}

func encodeValue(w io.Writer, t Type, value interface{}, length uint32) error {
	switch t {
	case TypeStructure:
		// Structure는 중첩된 TTLV 아이템들
		if items, ok := value.([]*TTLVItem); ok {
			for _, item := range items {
				if err := EncodeTTLV(w, item); err != nil {
					return err
				}
			}
		}
		return nil
		
	case TypeInteger, TypeEnumeration:
		// 4바이트 정수, 8바이트로 패딩
		buf := make([]byte, 8)
		if val, ok := value.(int32); ok {
			binary.BigEndian.PutUint32(buf[4:], uint32(val))
		} else if val, ok := value.(uint32); ok {
			binary.BigEndian.PutUint32(buf[4:], val)
		}
		_, err := w.Write(buf)
		return err
		
	case TypeLongInteger:
		// 8바이트 정수
		buf := make([]byte, 8)
		if val, ok := value.(int64); ok {
			binary.BigEndian.PutUint64(buf, uint64(val))
		} else if val, ok := value.(uint64); ok {
			binary.BigEndian.PutUint64(buf, val)
		}
		_, err := w.Write(buf)
		return err
		
	case TypeTextString:
		// 문자열 + 패딩
		if str, ok := value.(string); ok {
			strBytes := []byte(str)
			if _, err := w.Write(strBytes); err != nil {
				return err
			}
			// 8바이트 경계로 패딩
			padding := (8 - (len(strBytes) % 8)) % 8
			if padding > 0 {
				_, err := w.Write(make([]byte, padding))
				return err
			}
		}
		return nil
		
	case TypeByteString:
		// 바이트 배열 + 패딩
		if bytes, ok := value.([]byte); ok {
			if _, err := w.Write(bytes); err != nil {
				return err
			}
			// 8바이트 경계로 패딩
			padding := (8 - (len(bytes) % 8)) % 8
			if padding > 0 {
				_, err := w.Write(make([]byte, padding))
				return err
			}
		}
		return nil
		
	case TypeBoolean:
		// 8바이트 불린
		buf := make([]byte, 8)
		if val, ok := value.(bool); ok && val {
			binary.BigEndian.PutUint64(buf, 1)
		}
		_, err := w.Write(buf)
		return err
		
	default:
		return errors.New("unsupported TTLV type")
	}
}

// TTLV 디코더
func DecodeTTLV(r io.Reader) (*TTLVItem, error) {
	// Tag (3 bytes) + Type (1 byte) 읽기
	tagTypeBytes := make([]byte, 4)
	if _, err := io.ReadFull(r, tagTypeBytes); err != nil {
		return nil, err
	}
	
	// 3바이트 태그를 4바이트로 변환
	tagBytes := make([]byte, 4)
	tagBytes[1] = tagTypeBytes[0]
	tagBytes[2] = tagTypeBytes[1]
	tagBytes[3] = tagTypeBytes[2]
	tag := Tag(binary.BigEndian.Uint32(tagBytes))
	itemType := Type(tagTypeBytes[3])
	
	// Length 읽기
	lengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(r, lengthBytes); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lengthBytes)
	
	// Value 읽기
	value, err := decodeValue(r, itemType, length)
	if err != nil {
		return nil, err
	}
	
	return &TTLVItem{
		Tag:    tag,
		Type:   itemType,
		Length: length,
		Value:  value,
	}, nil
}

func decodeValue(r io.Reader, t Type, length uint32) (interface{}, error) {
	switch t {
	case TypeStructure:
		// Structure는 중첩된 TTLV 아이템들
		items := make([]*TTLVItem, 0)
		bytesRead := uint32(0)
		
		for bytesRead < length {
			item, err := DecodeTTLV(r)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
			// 각 아이템은 8바이트 + value (8바이트 경계로 패딩됨)
			itemSize := uint32(8) + paddedLength(item.Length)
			bytesRead += itemSize
		}
		return items, nil
		
	case TypeInteger, TypeEnumeration:
		// 8바이트 읽기 (4바이트 값 + 4바이트 패딩)
		buf := make([]byte, 8)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return int32(binary.BigEndian.Uint32(buf[4:])), nil
		
	case TypeLongInteger:
		// 8바이트 읽기
		buf := make([]byte, 8)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return int64(binary.BigEndian.Uint64(buf)), nil
		
	case TypeTextString:
		// 문자열 + 패딩 읽기
		paddedLen := paddedLength(length)
		buf := make([]byte, paddedLen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf[:length]), nil
		
	case TypeByteString:
		// 바이트 배열 + 패딩 읽기
		paddedLen := paddedLength(length)
		buf := make([]byte, paddedLen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return buf[:length], nil
		
	case TypeBoolean:
		// 8바이트 읽기
		buf := make([]byte, 8)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return binary.BigEndian.Uint64(buf) != 0, nil
		
	default:
		return nil, errors.New("unsupported TTLV type")
	}
}

// 8바이트 경계로 패딩된 길이 계산
func paddedLength(length uint32) uint32 {
	return ((length + 7) / 8) * 8
}
