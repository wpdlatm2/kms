package main

import (
	"fmt"
	"log"
	"kmip-server/kmip"
)

func main() {
	fmt.Println("=== KMIP Raft Replication Examples ===\n")
	
	// 예제 1: 코드로 설정
	example1()
	
	// 예제 2: YAML 파일에서 로드
	example2()
	
	// 예제 3: 다양한 복제 모드
	example3()
}

// 예제 1: 코드로 설정
func example1() {
	fmt.Println("예제 1: 코드로 Raft 설정")
	fmt.Println("---")
	
	// 쿼럼 모드 설정
	config := &kmip.RaftConfig{
		NodeID:              "node-1",
		BindAddr:            "127.0.0.1:7000",
		DataDir:             "./data/node-1",
		Bootstrap:           true,
		ReplicationEnabled:  true,
		ReplicationFactor:   3,
		MinReplicas:         2,
		InitialPeers: []kmip.PeerConfig{
			{ID: "node-2", Address: "127.0.0.1:7001"},
			{ID: "node-3", Address: "127.0.0.1:7002"},
		},
	}
	
	policy := &kmip.ReplicationPolicy{
		Mode:              kmip.ReplicationModeQuorum,
		MinAcks:           2,
		TimeoutMs:         5000,
		RetryAttempts:     3,
		RetryBackoffMs:    100,
		ConsistencyLevel:  "strong",
	}
	
	// Raft 저장소 생성
	store, err := kmip.NewRaftStore(config, policy)
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}
	
	fmt.Printf("✓ Raft 저장소 생성 완료\n")
	fmt.Printf("  - Node ID: %s\n", config.NodeID)
	fmt.Printf("  - Replication Mode: %s\n", policy.Mode)
	fmt.Printf("  - Min Replicas: %d\n", config.MinReplicas)
	fmt.Println()
	
	_ = store
}

// 예제 2: YAML 파일에서 로드
func example2() {
	fmt.Println("예제 2: YAML 파일에서 설정 로드")
	fmt.Println("---")
	
	// YAML 파일에서 설정 로드
	config, policy, err := kmip.LoadConfigFromYAML("config/raft-config.yaml")
	if err != nil {
		log.Printf("Error loading config: %v", err)
		
		// 기본 설정 사용
		fmt.Println("⚠️  YAML 파일이 없어 기본 설정 사용")
		config = kmip.DefaultRaftConfig()
		policy = kmip.DefaultReplicationPolicy()
	}
	
	fmt.Printf("✓ 설정 로드 완료\n")
	fmt.Printf("  - Node ID: %s\n", config.NodeID)
	fmt.Printf("  - Bind Address: %s\n", config.BindAddr)
	fmt.Printf("  - Data Directory: %s\n", config.DataDir)
	fmt.Printf("  - Replication Enabled: %v\n", config.ReplicationEnabled)
	if config.ReplicationEnabled {
		fmt.Printf("  - Replication Factor: %d\n", config.ReplicationFactor)
		fmt.Printf("  - Replication Mode: %s\n", policy.Mode)
		fmt.Printf("  - Consistency Level: %s\n", policy.ConsistencyLevel)
	}
	fmt.Println()
}

// 예제 3: 다양한 복제 모드
func example3() {
	fmt.Println("예제 3: 다양한 복제 모드")
	fmt.Println("---")
	
	// 모드 1: 쿼럼 (권장)
	fmt.Println("모드 1: Quorum (과반수)")
	quorumConfig := &kmip.RaftConfig{
		NodeID:              "node-1",
		BindAddr:            "127.0.0.1:7000",
		DataDir:             "./data/quorum",
		ReplicationEnabled:  true,
		ReplicationFactor:   3,
		MinReplicas:         2,  // 3/2 = 2 (과반수)
	}
	quorumPolicy := &kmip.ReplicationPolicy{
		Mode:              kmip.ReplicationModeQuorum,
		MinAcks:           2,
		TimeoutMs:         5000,
		ConsistencyLevel:  "strong",
	}
	fmt.Printf("  - 복제 팩터: %d\n", quorumConfig.ReplicationFactor)
	fmt.Printf("  - 필요 ACK: %d/%d\n", quorumPolicy.MinAcks, quorumConfig.ReplicationFactor)
	fmt.Printf("  - 특징: 균형잡힌 성능과 안전성\n")
	fmt.Println()
	
	// 모드 2: 동기 (최대 안전성)
	fmt.Println("모드 2: Sync (동기 복제)")
	syncConfig := &kmip.RaftConfig{
		NodeID:              "node-1",
		BindAddr:            "127.0.0.1:7000",
		DataDir:             "./data/sync",
		ReplicationEnabled:  true,
		ReplicationFactor:   3,
		MinReplicas:         3,  // 모든 노드
	}
	syncPolicy := &kmip.ReplicationPolicy{
		Mode:              kmip.ReplicationModeSync,
		MinAcks:           3,
		TimeoutMs:         10000,
		ConsistencyLevel:  "strong",
	}
	fmt.Printf("  - 복제 팩터: %d\n", syncConfig.ReplicationFactor)
	fmt.Printf("  - 필요 ACK: %d/%d (모두)\n", syncPolicy.MinAcks, syncConfig.ReplicationFactor)
	fmt.Printf("  - 특징: 최고 안전성, 느린 성능\n")
	fmt.Println()
	
	// 모드 3: 비동기 (최대 성능)
	fmt.Println("모드 3: Async (비동기 복제)")
	asyncConfig := &kmip.RaftConfig{
		NodeID:              "node-1",
		BindAddr:            "127.0.0.1:7000",
		DataDir:             "./data/async",
		ReplicationEnabled:  true,
		ReplicationFactor:   3,
		MinReplicas:         1,  // 리더만
	}
	asyncPolicy := &kmip.ReplicationPolicy{
		Mode:              kmip.ReplicationModeAsync,
		MinAcks:           1,
		TimeoutMs:         1000,
		ConsistencyLevel:  "eventual",
	}
	fmt.Printf("  - 복제 팩터: %d\n", asyncConfig.ReplicationFactor)
	fmt.Printf("  - 필요 ACK: %d (리더만)\n", asyncPolicy.MinAcks)
	fmt.Printf("  - 특징: 최고 성능, 데이터 손실 가능\n")
	fmt.Println()
	
	// 모드 4: 로컬 (복제 없음)
	fmt.Println("모드 4: Local (복제 비활성화)")
	localConfig := &kmip.RaftConfig{
		NodeID:              "standalone",
		BindAddr:            "127.0.0.1:7000",
		DataDir:             "./data/local",
		ReplicationEnabled:  false,
	}
	fmt.Printf("  - 복제: 비활성화\n")
	fmt.Printf("  - 특징: 단일 노드, 개발/테스트용\n")
	fmt.Println()
	
	_, _ = quorumConfig, quorumPolicy
	_, _ = syncConfig, syncPolicy
	_, _ = asyncConfig, asyncPolicy
	_, _ = localConfig
}
