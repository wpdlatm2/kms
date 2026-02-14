package kmip

import (
	"time"
)

// ProtocolVersion 구조체
type ProtocolVersion struct {
	Major int32
	Minor int32
}

// KMIP 버전 정의
var (
	Version1_0 = ProtocolVersion{Major: 1, Minor: 0}
	Version1_1 = ProtocolVersion{Major: 1, Minor: 1}
	Version1_2 = ProtocolVersion{Major: 1, Minor: 2}
	Version1_3 = ProtocolVersion{Major: 1, Minor: 3}
	Version1_4 = ProtocolVersion{Major: 1, Minor: 4}
	Version2_0 = ProtocolVersion{Major: 2, Minor: 0}
	Version2_1 = ProtocolVersion{Major: 2, Minor: 1}
	Version3_0 = ProtocolVersion{Major: 3, Minor: 0}
)

// 지원하는 버전 목록
var SupportedVersions = []ProtocolVersion{
	Version1_0, Version1_1, Version1_2, Version1_3, Version1_4,
	Version2_0, Version2_1, Version3_0,
}

// RequestHeader 구조체
type RequestHeader struct {
	ProtocolVersion      ProtocolVersion
	MaximumResponseSize  *int32
	BatchCount           int32
	TimeStamp            *time.Time
}

// ResponseHeader 구조체
type ResponseHeader struct {
	ProtocolVersion ProtocolVersion
	TimeStamp       time.Time
	BatchCount      int32
}

// BatchRequestItem 구조체
type BatchRequestItem struct {
	Operation          int32
	UniqueIdentifier   *string
	RequestPayload     interface{}
}

// BatchResponseItem 구조체
type BatchResponseItem struct {
	Operation          int32
	ResultStatus       int32
	ResultReason       *int32
	ResultMessage      *string
	UniqueIdentifier   *string
	ResponsePayload    interface{}
}

// RequestMessage 구조체
type RequestMessage struct {
	RequestHeader RequestHeader
	BatchItems    []BatchRequestItem
}

// ResponseMessage 구조체
type ResponseMessage struct {
	ResponseHeader ResponseHeader
	BatchItems     []BatchResponseItem
}

// ManagedObject 인터페이스
type ManagedObject interface {
	GetObjectType() int32
	GetUniqueIdentifier() string
	GetAttributes() map[string]interface{}
}

// SymmetricKey 구조체
type SymmetricKey struct {
	UniqueIdentifier string
	KeyBlock         KeyBlock
	Attributes       map[string]interface{}
}

func (k *SymmetricKey) GetObjectType() int32 {
	return ObjectTypeSymmetricKey
}

func (k *SymmetricKey) GetUniqueIdentifier() string {
	return k.UniqueIdentifier
}

func (k *SymmetricKey) GetAttributes() map[string]interface{} {
	return k.Attributes
}

// PublicKey 구조체
type PublicKey struct {
	UniqueIdentifier string
	KeyBlock         KeyBlock
	Attributes       map[string]interface{}
}

func (k *PublicKey) GetObjectType() int32 {
	return ObjectTypePublicKey
}

func (k *PublicKey) GetUniqueIdentifier() string {
	return k.UniqueIdentifier
}

func (k *PublicKey) GetAttributes() map[string]interface{} {
	return k.Attributes
}

// PrivateKey 구조체
type PrivateKey struct {
	UniqueIdentifier string
	KeyBlock         KeyBlock
	Attributes       map[string]interface{}
}

func (k *PrivateKey) GetObjectType() int32 {
	return ObjectTypePrivateKey
}

func (k *PrivateKey) GetUniqueIdentifier() string {
	return k.UniqueIdentifier
}

func (k *PrivateKey) GetAttributes() map[string]interface{} {
	return k.Attributes
}

// KeyBlock 구조체
type KeyBlock struct {
	KeyFormatType          int32
	KeyValue               KeyValue
	CryptographicAlgorithm *int32
	CryptographicLength    *int32
}

// KeyValue 구조체
type KeyValue struct {
	KeyMaterial []byte
	Attributes  map[string]interface{}
}

// CreateRequest 페이로드
type CreateRequest struct {
	ObjectType int32
	Attributes map[string]interface{}
}

// CreateResponse 페이로드
type CreateResponse struct {
	ObjectType       int32
	UniqueIdentifier string
}

// GetRequest 페이로드
type GetRequest struct {
	UniqueIdentifier *string
	KeyFormatType    *int32
}

// GetResponse 페이로드
type GetResponse struct {
	ObjectType   int32
	UniqueIdentifier string
	Object       ManagedObject
}

// DestroyRequest 페이로드
type DestroyRequest struct {
	UniqueIdentifier *string
}

// DestroyResponse 페이로드
type DestroyResponse struct {
	UniqueIdentifier string
}

// QueryRequest 페이로드
type QueryRequest struct {
	QueryFunctions []int32
}

// QueryResponse 페이로드
type QueryResponse struct {
	Operations              []int32
	ObjectTypes             []int32
	VendorIdentification    *string
	ServerInformation       *string
	ProtocolVersions        []ProtocolVersion
}

// DiscoverVersionsRequest 페이로드
type DiscoverVersionsRequest struct {
	ProtocolVersions []ProtocolVersion
}

// DiscoverVersionsResponse 페이로드
type DiscoverVersionsResponse struct {
	ProtocolVersions []ProtocolVersion
}

// RegisterRequest는 Register 요청 (외부 키 등록)
type RegisterRequest struct {
	ObjectType    int32
	ManagedObject ManagedObject
	Attributes    map[string]interface{}
}

// RegisterResponse는 Register 응답
type RegisterResponse struct {
	UniqueIdentifier string
}

// LocateRequest는 Locate 요청 (키 검색)
type LocateRequest struct {
	MaximumItems *int32
	OffsetItems  *int32
	Attributes   map[string]interface{}
}

// LocateResponse는 Locate 응답
type LocateResponse struct {
	LocatedItems      int32
	UniqueIdentifiers []string
}

// Attribute는 KMIP 속성
type Attribute struct {
	Name  string
	Value interface{}
}

// AlternateName은 키의 대체 이름
type AlternateName struct {
	Value string
	Type  string // "UninterpretedTextString", "URI", etc.
}

// GetAttributesRequest는 GetAttributes 요청
type GetAttributesRequest struct {
	UniqueIdentifier *string
	AttributeNames   []string
}

// GetAttributesResponse는 GetAttributes 응답
type GetAttributesResponse struct {
	UniqueIdentifier string
	Attributes       map[string]interface{}
}

// AddAttributeRequest는 AddAttribute 요청
type AddAttributeRequest struct {
	UniqueIdentifier *string
	Attribute        map[string]interface{}
}

// AddAttributeResponse는 AddAttribute 응답
type AddAttributeResponse struct {
	UniqueIdentifier string
}

// ModifyAttributeRequest는 ModifyAttribute 요청
type ModifyAttributeRequest struct {
	UniqueIdentifier *string
	Attribute        map[string]interface{}
}

// ModifyAttributeResponse는 ModifyAttribute 응답
type ModifyAttributeResponse struct {
	UniqueIdentifier string
}

// DeleteAttributeRequest는 DeleteAttribute 요청
type DeleteAttributeRequest struct {
	UniqueIdentifier *string
	AttributeName    string
	AttributeIndex   *int32
}

// DeleteAttributeResponse는 DeleteAttribute 응답
type DeleteAttributeResponse struct {
	UniqueIdentifier string
}

// RekeyRequest는 Rekey 요청
type RekeyRequest struct {
	UniqueIdentifier *string
	OffsetValue      *int32
	Attributes       map[string]interface{}
}

// RekeyResponse는 Rekey 응답
type RekeyResponse struct {
	UniqueIdentifier string
}
