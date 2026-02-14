package kmip

import (
	"bytes"
	"crypto/rand"
	"errors"
	"time"
)

// Server는 KMIP 서버
type Server struct {
	store            ObjectStore
	supportedVersions []ProtocolVersion
	keyGenerator     KeyGenerator
}

// NewServer는 새로운 KMIP 서버를 생성
func NewServer(store ObjectStore) *Server {
	return &Server{
		store:            store,
		supportedVersions: SupportedVersions,
		keyGenerator:     NewKeyGenerator(),
	}
}

// ProcessRequest는 요청 메시지를 처리하고 응답 메시지를 반환
func (s *Server) ProcessRequest(reqData []byte) ([]byte, error) {
	// 요청 파싱
	req, err := s.parseRequest(reqData)
	if err != nil {
		return nil, err
	}
	
	// 응답 생성
	resp := s.handleRequest(req)
	
	// 응답 인코딩
	return s.encodeResponse(resp)
}

// parseRequest는 TTLV 데이터를 RequestMessage로 파싱
func (s *Server) parseRequest(data []byte) (*RequestMessage, error) {
	reader := bytes.NewReader(data)
	item, err := DecodeTTLV(reader)
	if err != nil {
		return nil, err
	}
	
	if item.Tag != TagRequestMessage {
		return nil, errors.New("invalid request message tag")
	}
	
	items, ok := item.Value.([]*TTLVItem)
	if !ok {
		return nil, errors.New("invalid request message structure")
	}
	
	req := &RequestMessage{}
	
	for _, subItem := range items {
		switch subItem.Tag {
		case TagRequestHeader:
			header, err := s.parseRequestHeader(subItem)
			if err != nil {
				return nil, err
			}
			req.RequestHeader = *header
			
		case TagBatchItem:
			batchItem, err := s.parseBatchRequestItem(subItem)
			if err != nil {
				return nil, err
			}
			req.BatchItems = append(req.BatchItems, *batchItem)
		}
	}
	
	return req, nil
}

// parseRequestHeader는 요청 헤더를 파싱
func (s *Server) parseRequestHeader(item *TTLVItem) (*RequestHeader, error) {
	items, ok := item.Value.([]*TTLVItem)
	if !ok {
		return nil, errors.New("invalid request header structure")
	}
	
	header := &RequestHeader{}
	
	for _, subItem := range items {
		switch subItem.Tag {
		case TagProtocolVersion:
			version, err := s.parseProtocolVersion(subItem)
			if err != nil {
				return nil, err
			}
			header.ProtocolVersion = *version
			
		case TagBatchCount:
			if count, ok := subItem.Value.(int32); ok {
				header.BatchCount = count
			}
		}
	}
	
	return header, nil
}

// parseProtocolVersion은 프로토콜 버전을 파싱
func (s *Server) parseProtocolVersion(item *TTLVItem) (*ProtocolVersion, error) {
	items, ok := item.Value.([]*TTLVItem)
	if !ok {
		return nil, errors.New("invalid protocol version structure")
	}
	
	version := &ProtocolVersion{}
	
	for _, subItem := range items {
		switch subItem.Tag {
		case TagProtocolVersionMajor:
			if major, ok := subItem.Value.(int32); ok {
				version.Major = major
			}
		case TagProtocolVersionMinor:
			if minor, ok := subItem.Value.(int32); ok {
				version.Minor = minor
			}
		}
	}
	
	return version, nil
}

// parseBatchRequestItem은 배치 요청 아이템을 파싱
func (s *Server) parseBatchRequestItem(item *TTLVItem) (*BatchRequestItem, error) {
	items, ok := item.Value.([]*TTLVItem)
	if !ok {
		return nil, errors.New("invalid batch item structure")
	}
	
	batchItem := &BatchRequestItem{}
	
	for _, subItem := range items {
		switch subItem.Tag {
		case TagOperation:
			if op, ok := subItem.Value.(int32); ok {
				batchItem.Operation = op
			}
		case TagUniqueIdentifier:
			if id, ok := subItem.Value.(string); ok {
				batchItem.UniqueIdentifier = &id
			}
		}
	}
	
	return batchItem, nil
}

// handleRequest는 요청을 처리하고 응답을 생성
func (s *Server) handleRequest(req *RequestMessage) *ResponseMessage {
	resp := &ResponseMessage{
		ResponseHeader: ResponseHeader{
			ProtocolVersion: req.RequestHeader.ProtocolVersion,
			TimeStamp:       time.Now(),
			BatchCount:      int32(len(req.BatchItems)),
		},
		BatchItems: make([]BatchResponseItem, 0, len(req.BatchItems)),
	}
	
	for _, reqItem := range req.BatchItems {
		respItem := s.handleOperation(&reqItem)
		resp.BatchItems = append(resp.BatchItems, respItem)
	}
	
	return resp
}

// handleOperation은 개별 작업을 처리
func (s *Server) handleOperation(req *BatchRequestItem) BatchResponseItem {
	resp := BatchResponseItem{
		Operation: req.Operation,
	}
	
	switch req.Operation {
	case OperationCreate:
		return s.handleCreate(req)
	case OperationCreateKeyPair:
		return s.handleCreateKeyPair(req)
	case OperationRegister:
		return s.handleRegister(req)
	case OperationGet:
		return s.handleGet(req)
	case OperationLocate:
		return s.handleLocate(req)
	case OperationGetAttributes:
		return s.handleGetAttributes(req)
	case OperationAddAttribute:
		return s.handleAddAttribute(req)
	case OperationModifyAttribute:
		return s.handleModifyAttribute(req)
	case OperationDeleteAttribute:
		return s.handleDeleteAttribute(req)
	case OperationRekey:
		return s.handleRekey(req)
	case OperationDestroy:
		return s.handleDestroy(req)
	case OperationQuery:
		return s.handleQuery(req)
	case OperationDiscoverVersions:
		return s.handleDiscoverVersions(req)
	default:
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "Unsupported operation"
		resp.ResultMessage = &msg
	}
	
	return resp
}

// handleCreate는 Create 작업 처리
func (s *Server) handleCreate(req *BatchRequestItem) BatchResponseItem {
	resp := BatchResponseItem{
		Operation: OperationCreate,
	}
	
	// CreateRequest에서 정보 추출
	createReq, ok := req.RequestPayload.(*CreateRequest)
	if !ok {
		// 기본값 사용
		createReq = &CreateRequest{
			ObjectType: ObjectTypeSymmetricKey,
			Attributes: make(map[string]interface{}),
		}
	}
	
	// 속성에서 알고리즘과 길이 추출
	algorithm := int32(CryptoAlgorithmAES) // 기본값
	length := int32(256)                   // 기본값
	
	if algo, ok := createReq.Attributes["CryptographicAlgorithm"].(int32); ok {
		algorithm = algo
	}
	if len, ok := createReq.Attributes["CryptographicLength"].(int32); ok {
		length = len
	}
	
	var obj ManagedObject
	id := s.store.GenerateUniqueID()
	
	switch createReq.ObjectType {
	case ObjectTypeSymmetricKey:
		// 대칭 키 생성
		keyMaterial, err := s.keyGenerator.GenerateSymmetricKey(algorithm, length)
		if err != nil {
			resp.ResultStatus = ResultStatusOperationFailed
			msg := fmt.Sprintf("Failed to generate symmetric key: %v", err)
			resp.ResultMessage = &msg
			return resp
		}
		
		obj = &SymmetricKey{
			UniqueIdentifier: id,
			KeyBlock: KeyBlock{
				KeyFormatType: 0x00000001, // Raw
				KeyValue: KeyValue{
					KeyMaterial: keyMaterial,
					Attributes:  make(map[string]interface{}),
				},
				CryptographicAlgorithm: &algorithm,
				CryptographicLength:    &length,
			},
			Attributes: createReq.Attributes,
		}
		
	default:
		resp.ResultStatus = ResultStatusOperationFailed
		msg := fmt.Sprintf("Unsupported object type for Create: %d", createReq.ObjectType)
		resp.ResultMessage = &msg
		return resp
	}
	
	if err := s.store.Store(obj); err != nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := err.Error()
		resp.ResultMessage = &msg
		return resp
	}
	
	resp.ResultStatus = ResultStatusSuccess
	resp.UniqueIdentifier = &id
	
	return resp
}

// handleCreateKeyPair는 CreateKeyPair 작업 처리 (RSA, ECDSA)
func (s *Server) handleCreateKeyPair(req *BatchRequestItem) BatchResponseItem {
	resp := BatchResponseItem{
		Operation: OperationCreateKeyPair,
	}
	
	// CreateRequest에서 정보 추출
	createReq, ok := req.RequestPayload.(*CreateRequest)
	if !ok {
		createReq = &CreateRequest{
			Attributes: make(map[string]interface{}),
		}
	}
	
	// 속성에서 알고리즘과 길이 추출
	algorithm := int32(CryptoAlgorithmRSA) // 기본값
	length := int32(2048)                   // 기본값
	
	if algo, ok := createReq.Attributes["CryptographicAlgorithm"].(int32); ok {
		algorithm = algo
	}
	if len, ok := createReq.Attributes["CryptographicLength"].(int32); ok {
		length = len
	}
	
	var publicKeyMaterial, privateKeyMaterial []byte
	var err error
	
	switch algorithm {
	case CryptoAlgorithmRSA:
		// RSA 키 쌍 생성
		publicKeyMaterial, privateKeyMaterial, err = s.keyGenerator.GenerateRSAKeyPair(length)
		if err != nil {
			resp.ResultStatus = ResultStatusOperationFailed
			msg := fmt.Sprintf("Failed to generate RSA key pair: %v", err)
			resp.ResultMessage = &msg
			return resp
		}
		
	case CryptoAlgorithmECDSA:
		// ECDSA 키 쌍 생성
		curveName := GetCurveName(length)
		publicKeyMaterial, privateKeyMaterial, err = s.keyGenerator.GenerateECDSAKeyPair(curveName)
		if err != nil {
			resp.ResultStatus = ResultStatusOperationFailed
			msg := fmt.Sprintf("Failed to generate ECDSA key pair: %v", err)
			resp.ResultMessage = &msg
			return resp
		}
		
	default:
		resp.ResultStatus = ResultStatusOperationFailed
		msg := fmt.Sprintf("Unsupported algorithm for CreateKeyPair: %d", algorithm)
		resp.ResultMessage = &msg
		return resp
	}
	
	// 공개 키 저장
	publicKeyID := s.store.GenerateUniqueID()
	publicKey := &PublicKey{
		UniqueIdentifier: publicKeyID,
		KeyBlock: KeyBlock{
			KeyFormatType: 0x00000002, // PKCS#1 or X.509
			KeyValue: KeyValue{
				KeyMaterial: publicKeyMaterial,
				Attributes:  make(map[string]interface{}),
			},
			CryptographicAlgorithm: &algorithm,
			CryptographicLength:    &length,
		},
		Attributes: createReq.Attributes,
	}
	
	if err := s.store.Store(publicKey); err != nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := err.Error()
		resp.ResultMessage = &msg
		return resp
	}
	
	// 개인 키 저장
	privateKeyID := s.store.GenerateUniqueID()
	privateKey := &PrivateKey{
		UniqueIdentifier: privateKeyID,
		KeyBlock: KeyBlock{
			KeyFormatType: 0x00000002, // PKCS#1 or PKCS#8
			KeyValue: KeyValue{
				KeyMaterial: privateKeyMaterial,
				Attributes:  make(map[string]interface{}),
			},
			CryptographicAlgorithm: &algorithm,
			CryptographicLength:    &length,
		},
		Attributes: createReq.Attributes,
	}
	
	if err := s.store.Store(privateKey); err != nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := err.Error()
		resp.ResultMessage = &msg
		return resp
	}
	
	resp.ResultStatus = ResultStatusSuccess
	// 공개 키와 개인 키 ID를 모두 반환 (간단히 공개 키 ID만)
	resp.UniqueIdentifier = &publicKeyID
	
	// ResponsePayload에 키 쌍 정보 저장
	resp.ResponsePayload = map[string]string{
		"public_key_id":  publicKeyID,
		"private_key_id": privateKeyID,
	}
	
	return resp
}

// handleGet는 Get 작업 처리
func (s *Server) handleGet(req *BatchRequestItem) BatchResponseItem {
	resp := BatchResponseItem{
		Operation: OperationGet,
	}
	
	if req.UniqueIdentifier == nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "Unique identifier required"
		resp.ResultMessage = &msg
		return resp
	}
	
	obj, err := s.store.Retrieve(*req.UniqueIdentifier)
	if err != nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := err.Error()
		resp.ResultMessage = &msg
		return resp
	}
	
	resp.ResultStatus = ResultStatusSuccess
	resp.UniqueIdentifier = req.UniqueIdentifier
	resp.ResponsePayload = obj
	
	return resp
}

// handleRegister는 Register 작업 처리 (외부 키 등록)
func (s *Server) handleRegister(req *BatchRequestItem) BatchResponseItem {
	resp := BatchResponseItem{
		Operation: OperationRegister,
	}
	
	registerReq, ok := req.RequestPayload.(*RegisterRequest)
	if !ok {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "Invalid Register request"
		resp.ResultMessage = &msg
		return resp
	}
	
	// 새로운 ID 생성
	id := s.store.GenerateUniqueID()
	
	// ManagedObject의 ID 설정
	switch obj := registerReq.ManagedObject.(type) {
	case *SymmetricKey:
		obj.UniqueIdentifier = id
		if registerReq.Attributes != nil {
			obj.Attributes = registerReq.Attributes
		}
	case *PublicKey:
		obj.UniqueIdentifier = id
		if registerReq.Attributes != nil {
			obj.Attributes = registerReq.Attributes
		}
	case *PrivateKey:
		obj.UniqueIdentifier = id
		if registerReq.Attributes != nil {
			obj.Attributes = registerReq.Attributes
		}
	}
	
	// 객체 저장
	if err := s.store.Store(registerReq.ManagedObject); err != nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := err.Error()
		resp.ResultMessage = &msg
		return resp
	}
	
	resp.ResultStatus = ResultStatusSuccess
	resp.UniqueIdentifier = &id
	resp.ResponsePayload = &RegisterResponse{
		UniqueIdentifier: id,
	}
	
	return resp
}

// handleLocate는 Locate 작업 처리 (키 검색)
func (s *Server) handleLocate(req *BatchRequestItem) BatchResponseItem {
	resp := BatchResponseItem{
		Operation: OperationLocate,
	}
	
	locateReq, ok := req.RequestPayload.(*LocateRequest)
	if !ok {
		locateReq = &LocateRequest{}
	}
	
	// 모든 객체 조회
	objects := s.store.List()
	
	// 필터링
	var matchedIDs []string
	for _, obj := range objects {
		if s.matchesAttributes(obj, locateReq.Attributes) {
			matchedIDs = append(matchedIDs, obj.GetUniqueIdentifier())
		}
	}
	
	// 페이지네이션 적용
	offset := int32(0)
	if locateReq.OffsetItems != nil {
		offset = *locateReq.OffsetItems
	}
	
	maximum := int32(len(matchedIDs))
	if locateReq.MaximumItems != nil && *locateReq.MaximumItems < maximum {
		maximum = *locateReq.MaximumItems
	}
	
	// 결과 슬라이스
	var resultIDs []string
	for i := offset; i < offset+maximum && int(i) < len(matchedIDs); i++ {
		resultIDs = append(resultIDs, matchedIDs[i])
	}
	
	resp.ResultStatus = ResultStatusSuccess
	resp.ResponsePayload = &LocateResponse{
		LocatedItems:      int32(len(resultIDs)),
		UniqueIdentifiers: resultIDs,
	}
	
	return resp
}

// matchesAttributes는 객체가 속성 필터와 일치하는지 확인
func (s *Server) matchesAttributes(obj ManagedObject, filter map[string]interface{}) bool {
	if filter == nil || len(filter) == 0 {
		return true
	}
	
	objAttrs := obj.GetAttributes()
	for key, filterValue := range filter {
		// AlternateName 특별 처리
		if key == "AlternateName" {
			if altNames, ok := objAttrs["AlternateName"].([]interface{}); ok {
				matched := false
				for _, altName := range altNames {
					if altNameStr, ok := altName.(string); ok {
						if altNameStr == filterValue {
							matched = true
							break
						}
					} else if altNameMap, ok := altName.(map[string]interface{}); ok {
						if altNameMap["Value"] == filterValue {
							matched = true
							break
						}
					}
				}
				if !matched {
					return false
				}
				continue
			}
		}
		
		objValue, exists := objAttrs[key]
		if !exists {
			return false
		}
		if objValue != filterValue {
			return false
		}
	}
	
	return true
}

// handleGetAttributes는 GetAttributes 작업 처리
func (s *Server) handleGetAttributes(req *BatchRequestItem) BatchResponseItem {
	resp := BatchResponseItem{
		Operation: OperationGetAttributes,
	}
	
	getAttrsReq, ok := req.RequestPayload.(*GetAttributesRequest)
	if !ok || getAttrsReq.UniqueIdentifier == nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "Invalid GetAttributes request"
		resp.ResultMessage = &msg
		return resp
	}
	
	obj, err := s.store.Retrieve(*getAttrsReq.UniqueIdentifier)
	if err != nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "object not found"
		resp.ResultMessage = &msg
		return resp
	}
	
	// 요청된 속성만 반환 (비어있으면 모든 속성)
	attributes := make(map[string]interface{})
	allAttrs := obj.GetAttributes()
	
	if len(getAttrsReq.AttributeNames) == 0 {
		attributes = allAttrs
	} else {
		for _, attrName := range getAttrsReq.AttributeNames {
			if val, exists := allAttrs[attrName]; exists {
				attributes[attrName] = val
			}
		}
	}
	
	resp.ResultStatus = ResultStatusSuccess
	resp.UniqueIdentifier = getAttrsReq.UniqueIdentifier
	resp.ResponsePayload = &GetAttributesResponse{
		UniqueIdentifier: *getAttrsReq.UniqueIdentifier,
		Attributes:       attributes,
	}
	
	return resp
}

// handleAddAttribute는 AddAttribute 작업 처리
func (s *Server) handleAddAttribute(req *BatchRequestItem) BatchResponseItem {
	resp := BatchResponseItem{
		Operation: OperationAddAttribute,
	}
	
	addAttrReq, ok := req.RequestPayload.(*AddAttributeRequest)
	if !ok || addAttrReq.UniqueIdentifier == nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "Invalid AddAttribute request"
		resp.ResultMessage = &msg
		return resp
	}
	
	obj, err := s.store.Retrieve(*addAttrReq.UniqueIdentifier)
	if err != nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "object not found"
		resp.ResultMessage = &msg
		return resp
	}
	
	// 속성 추가
	attrs := obj.GetAttributes()
	for key, value := range addAttrReq.Attribute {
		attrs[key] = value
	}
	
	// 객체 업데이트
	if err := s.store.Store(obj); err != nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := err.Error()
		resp.ResultMessage = &msg
		return resp
	}
	
	resp.ResultStatus = ResultStatusSuccess
	resp.UniqueIdentifier = addAttrReq.UniqueIdentifier
	resp.ResponsePayload = &AddAttributeResponse{
		UniqueIdentifier: *addAttrReq.UniqueIdentifier,
	}
	
	return resp
}

// handleModifyAttribute는 ModifyAttribute 작업 처리
func (s *Server) handleModifyAttribute(req *BatchRequestItem) BatchResponseItem {
	resp := BatchResponseItem{
		Operation: OperationModifyAttribute,
	}
	
	modAttrReq, ok := req.RequestPayload.(*ModifyAttributeRequest)
	if !ok || modAttrReq.UniqueIdentifier == nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "Invalid ModifyAttribute request"
		resp.ResultMessage = &msg
		return resp
	}
	
	obj, err := s.store.Retrieve(*modAttrReq.UniqueIdentifier)
	if err != nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "object not found"
		resp.ResultMessage = &msg
		return resp
	}
	
	// 속성 수정
	attrs := obj.GetAttributes()
	for key, value := range modAttrReq.Attribute {
		attrs[key] = value
	}
	
	// 객체 업데이트
	if err := s.store.Store(obj); err != nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := err.Error()
		resp.ResultMessage = &msg
		return resp
	}
	
	resp.ResultStatus = ResultStatusSuccess
	resp.UniqueIdentifier = modAttrReq.UniqueIdentifier
	resp.ResponsePayload = &ModifyAttributeResponse{
		UniqueIdentifier: *modAttrReq.UniqueIdentifier,
	}
	
	return resp
}

// handleDeleteAttribute는 DeleteAttribute 작업 처리
func (s *Server) handleDeleteAttribute(req *BatchRequestItem) BatchResponseItem {
	resp := BatchResponseItem{
		Operation: OperationDeleteAttribute,
	}
	
	delAttrReq, ok := req.RequestPayload.(*DeleteAttributeRequest)
	if !ok || delAttrReq.UniqueIdentifier == nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "Invalid DeleteAttribute request"
		resp.ResultMessage = &msg
		return resp
	}
	
	obj, err := s.store.Retrieve(*delAttrReq.UniqueIdentifier)
	if err != nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "object not found"
		resp.ResultMessage = &msg
		return resp
	}
	
	// 속성 삭제
	attrs := obj.GetAttributes()
	delete(attrs, delAttrReq.AttributeName)
	
	// 객체 업데이트
	if err := s.store.Store(obj); err != nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := err.Error()
		resp.ResultMessage = &msg
		return resp
	}
	
	resp.ResultStatus = ResultStatusSuccess
	resp.UniqueIdentifier = delAttrReq.UniqueIdentifier
	resp.ResponsePayload = &DeleteAttributeResponse{
		UniqueIdentifier: *delAttrReq.UniqueIdentifier,
	}
	
	return resp
}

// handleRekey는 Rekey 작업 처리 (키 재생성)
func (s *Server) handleRekey(req *BatchRequestItem) BatchResponseItem {
	resp := BatchResponseItem{
		Operation: OperationRekey,
	}
	
	rekeyReq, ok := req.RequestPayload.(*RekeyRequest)
	if !ok || rekeyReq.UniqueIdentifier == nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "Invalid Rekey request"
		resp.ResultMessage = &msg
		return resp
	}
	
	// 기존 객체 조회
	oldObj, err := s.store.Retrieve(*rekeyReq.UniqueIdentifier)
	if err != nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "object not found"
		resp.ResultMessage = &msg
		return resp
	}
	
	// 새로운 키 생성
	newID := s.store.GenerateUniqueID()
	
	switch oldKey := oldObj.(type) {
	case *SymmetricKey:
		// 동일한 알고리즘과 길이로 새 키 생성
		algorithm := int32(CryptoAlgorithmAES)
		length := int32(256)
		
		if oldKey.KeyBlock.CryptographicAlgorithm != nil {
			algorithm = *oldKey.KeyBlock.CryptographicAlgorithm
		}
		if oldKey.KeyBlock.CryptographicLength != nil {
			length = *oldKey.KeyBlock.CryptographicLength
		}
		
		keyMaterial, err := s.keyGenerator.GenerateSymmetricKey(algorithm, length)
		if err != nil {
			resp.ResultStatus = ResultStatusOperationFailed
			msg := fmt.Sprintf("Failed to generate new key: %v", err)
			resp.ResultMessage = &msg
			return resp
		}
		
		// 새로운 키 객체 생성
		newKey := &SymmetricKey{
			UniqueIdentifier: newID,
			KeyBlock: KeyBlock{
				KeyFormatType: oldKey.KeyBlock.KeyFormatType,
				KeyValue: KeyValue{
					KeyMaterial: keyMaterial,
					Attributes:  make(map[string]interface{}),
				},
				CryptographicAlgorithm: &algorithm,
				CryptographicLength:    &length,
			},
			Attributes: make(map[string]interface{}),
		}
		
		// 기존 속성 복사 (옵션)
		if rekeyReq.Attributes != nil {
			newKey.Attributes = rekeyReq.Attributes
		} else {
			for k, v := range oldKey.Attributes {
				newKey.Attributes[k] = v
			}
		}
		
		// 새 키 저장
		if err := s.store.Store(newKey); err != nil {
			resp.ResultStatus = ResultStatusOperationFailed
			msg := err.Error()
			resp.ResultMessage = &msg
			return resp
		}
		
	default:
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "Rekey only supported for symmetric keys"
		resp.ResultMessage = &msg
		return resp
	}
	
	resp.ResultStatus = ResultStatusSuccess
	resp.UniqueIdentifier = &newID
	resp.ResponsePayload = &RekeyResponse{
		UniqueIdentifier: newID,
	}
	
	return resp
}

// handleDestroy는 Destroy 작업 처리
func (s *Server) handleDestroy(req *BatchRequestItem) BatchResponseItem {
	resp := BatchResponseItem{
		Operation: OperationDestroy,
	}
	
	if req.UniqueIdentifier == nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := "Unique identifier required"
		resp.ResultMessage = &msg
		return resp
	}
	
	if err := s.store.Delete(*req.UniqueIdentifier); err != nil {
		resp.ResultStatus = ResultStatusOperationFailed
		msg := err.Error()
		resp.ResultMessage = &msg
		return resp
	}
	
	resp.ResultStatus = ResultStatusSuccess
	resp.UniqueIdentifier = req.UniqueIdentifier
	
	return resp
}

// handleQuery는 Query 작업 처리
func (s *Server) handleQuery(req *BatchRequestItem) BatchResponseItem {
	resp := BatchResponseItem{
		Operation:    OperationQuery,
		ResultStatus: ResultStatusSuccess,
	}
	
	queryResp := &QueryResponse{
		Operations: []int32{
			OperationCreate,
			OperationCreateKeyPair,
			OperationRegister,
			OperationGet,
			OperationLocate,
			OperationGetAttributes,
			OperationAddAttribute,
			OperationModifyAttribute,
			OperationDeleteAttribute,
			OperationRekey,
			OperationDestroy,
			OperationQuery,
			OperationDiscoverVersions,
		},
		ObjectTypes: []int32{
			ObjectTypeSymmetricKey,
			ObjectTypePublicKey,
			ObjectTypePrivateKey,
		},
		ProtocolVersions: s.supportedVersions,
	}
	
	vendor := "KMIP Go Server"
	serverInfo := "KMIP 1.0-3.0 Compatible Server with RSA/ECDSA/SEED/ARIA Support"
	queryResp.VendorIdentification = &vendor
	queryResp.ServerInformation = &serverInfo
	
	resp.ResponsePayload = queryResp
	
	return resp
}

// handleDiscoverVersions는 DiscoverVersions 작업 처리
func (s *Server) handleDiscoverVersions(req *BatchRequestItem) BatchResponseItem {
	resp := BatchResponseItem{
		Operation:    OperationDiscoverVersions,
		ResultStatus: ResultStatusSuccess,
	}
	
	discoverResp := &DiscoverVersionsResponse{
		ProtocolVersions: s.supportedVersions,
	}
	
	resp.ResponsePayload = discoverResp
	
	return resp
}

// encodeResponse는 ResponseMessage를 TTLV로 인코딩
func (s *Server) encodeResponse(resp *ResponseMessage) ([]byte, error) {
	var buf bytes.Buffer
	
	// Response Message 구조 생성
	respItems := make([]*TTLVItem, 0)
	
	// Response Header
	headerItems := []*TTLVItem{
		{
			Tag:  TagProtocolVersion,
			Type: TypeStructure,
			Value: []*TTLVItem{
				{Tag: TagProtocolVersionMajor, Type: TypeInteger, Length: 4, Value: resp.ResponseHeader.ProtocolVersion.Major},
				{Tag: TagProtocolVersionMinor, Type: TypeInteger, Length: 4, Value: resp.ResponseHeader.ProtocolVersion.Minor},
			},
		},
		{Tag: TagTimeStamp, Type: TypeLongInteger, Length: 8, Value: resp.ResponseHeader.TimeStamp.Unix()},
		{Tag: TagBatchCount, Type: TypeInteger, Length: 4, Value: resp.ResponseHeader.BatchCount},
	}
	
	headerLength := s.calculateStructureLength(headerItems)
	respItems = append(respItems, &TTLVItem{
		Tag:    TagResponseHeader,
		Type:   TypeStructure,
		Length: headerLength,
		Value:  headerItems,
	})
	
	// Batch Items
	for _, batchItem := range resp.BatchItems {
		batchItems := []*TTLVItem{
			{Tag: TagOperation, Type: TypeEnumeration, Length: 4, Value: batchItem.Operation},
			{Tag: TagResultStatus, Type: TypeEnumeration, Length: 4, Value: batchItem.ResultStatus},
		}
		
		if batchItem.UniqueIdentifier != nil {
			idItem := &TTLVItem{
				Tag:    TagUniqueIdentifier,
				Type:   TypeTextString,
				Length: uint32(len(*batchItem.UniqueIdentifier)),
				Value:  *batchItem.UniqueIdentifier,
			}
			batchItems = append(batchItems, idItem)
		}
		
		if batchItem.ResultMessage != nil {
			msgItem := &TTLVItem{
				Tag:    TagResultMessage,
				Type:   TypeTextString,
				Length: uint32(len(*batchItem.ResultMessage)),
				Value:  *batchItem.ResultMessage,
			}
			batchItems = append(batchItems, msgItem)
		}
		
		batchLength := s.calculateStructureLength(batchItems)
		respItems = append(respItems, &TTLVItem{
			Tag:    TagBatchItem,
			Type:   TypeStructure,
			Length: batchLength,
			Value:  batchItems,
		})
	}
	
	// 전체 Response Message
	respLength := s.calculateStructureLength(respItems)
	responseMsg := &TTLVItem{
		Tag:    TagResponseMessage,
		Type:   TypeStructure,
		Length: respLength,
		Value:  respItems,
	}
	
	if err := EncodeTTLV(&buf, responseMsg); err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}

// calculateStructureLength는 Structure의 길이를 계산
func (s *Server) calculateStructureLength(items []*TTLVItem) uint32 {
	var length uint32
	for _, item := range items {
		// Tag(3) + Type(1) + Length(4) + Value (패딩 포함)
		length += 8 + paddedLength(item.Length)
	}
	return length
}
