package kmip

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"
	
	"gopkg.in/yaml.v2"
)

// ConfigFile은 설정 파일 구조
type ConfigFile struct {
	Node struct {
		ID        string `yaml:"id" json:"id"`
		BindAddr  string `yaml:"bind_addr" json:"bind_addr"`
		DataDir   string `yaml:"data_dir" json:"data_dir"`
		Bootstrap bool   `yaml:"bootstrap" json:"bootstrap"`
	} `yaml:"node" json:"node"`
	
	Replication struct {
		Enabled      bool   `yaml:"enabled" json:"enabled"`
		Factor       int    `yaml:"factor" json:"factor"`
		MinReplicas  int    `yaml:"min_replicas" json:"min_replicas"`
		Mode         string `yaml:"mode" json:"mode"`
		Consistency  string `yaml:"consistency" json:"consistency"`
		TimeoutMs    int    `yaml:"timeout_ms" json:"timeout_ms"`
		RetryAttempts int   `yaml:"retry_attempts" json:"retry_attempts"`
		RetryBackoffMs int  `yaml:"retry_backoff_ms" json:"retry_backoff_ms"`
	} `yaml:"replication" json:"replication"`
	
	Performance struct {
		HeartbeatTimeout  string `yaml:"heartbeat_timeout" json:"heartbeat_timeout"`
		ElectionTimeout   string `yaml:"election_timeout" json:"election_timeout"`
		CommitTimeout     string `yaml:"commit_timeout" json:"commit_timeout"`
		SnapshotInterval  string `yaml:"snapshot_interval" json:"snapshot_interval"`
		SnapshotThreshold uint64 `yaml:"snapshot_threshold" json:"snapshot_threshold"`
		MaxAppendEntries  int    `yaml:"max_append_entries" json:"max_append_entries"`
		TrailingLogs      uint64 `yaml:"trailing_logs" json:"trailing_logs"`
	} `yaml:"performance" json:"performance"`
	
	InitialPeers []struct {
		ID      string `yaml:"id" json:"id"`
		Address string `yaml:"address" json:"address"`
	} `yaml:"initial_peers" json:"initial_peers"`
}

// LoadConfigFromYAML은 YAML 파일에서 설정을 로드
func LoadConfigFromYAML(filename string) (*RaftConfig, *ReplicationPolicy, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %v", err)
	}
	
	var cf ConfigFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, nil, fmt.Errorf("failed to parse YAML: %v", err)
	}
	
	return configFileToRaftConfig(&cf)
}

// LoadConfigFromJSON은 JSON 파일에서 설정을 로드
func LoadConfigFromJSON(filename string) (*RaftConfig, *ReplicationPolicy, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %v", err)
	}
	
	var cf ConfigFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, nil, fmt.Errorf("failed to parse JSON: %v", err)
	}
	
	return configFileToRaftConfig(&cf)
}

// configFileToRaftConfig는 ConfigFile을 RaftConfig로 변환
func configFileToRaftConfig(cf *ConfigFile) (*RaftConfig, *ReplicationPolicy, error) {
	// 기본값 설정
	config := DefaultRaftConfig()
	policy := DefaultReplicationPolicy()
	
	// Node 설정
	if cf.Node.ID != "" {
		config.NodeID = cf.Node.ID
	}
	if cf.Node.BindAddr != "" {
		config.BindAddr = cf.Node.BindAddr
	}
	if cf.Node.DataDir != "" {
		config.DataDir = cf.Node.DataDir
	}
	config.Bootstrap = cf.Node.Bootstrap
	
	// Replication 설정
	if cf.Replication.Enabled {
		config.ReplicationEnabled = true
		if cf.Replication.Factor > 0 {
			config.ReplicationFactor = cf.Replication.Factor
		}
		if cf.Replication.MinReplicas > 0 {
			config.MinReplicas = cf.Replication.MinReplicas
		}
		
		// 복제 모드
		switch cf.Replication.Mode {
		case "sync":
			policy.Mode = ReplicationModeSync
		case "async":
			policy.Mode = ReplicationModeAsync
		case "quorum":
			policy.Mode = ReplicationModeQuorum
		}
		
		// 일관성 레벨
		if cf.Replication.Consistency != "" {
			policy.ConsistencyLevel = cf.Replication.Consistency
		}
		
		// 타임아웃 및 재시도
		if cf.Replication.TimeoutMs > 0 {
			policy.TimeoutMs = cf.Replication.TimeoutMs
		}
		if cf.Replication.RetryAttempts > 0 {
			policy.RetryAttempts = cf.Replication.RetryAttempts
		}
		if cf.Replication.RetryBackoffMs > 0 {
			policy.RetryBackoffMs = cf.Replication.RetryBackoffMs
		}
	} else {
		config.ReplicationEnabled = false
	}
	
	// Performance 설정
	if cf.Performance.HeartbeatTimeout != "" {
		if d, err := time.ParseDuration(cf.Performance.HeartbeatTimeout); err == nil {
			config.HeartbeatTimeout = d
		}
	}
	if cf.Performance.ElectionTimeout != "" {
		if d, err := time.ParseDuration(cf.Performance.ElectionTimeout); err == nil {
			config.ElectionTimeout = d
		}
	}
	if cf.Performance.CommitTimeout != "" {
		if d, err := time.ParseDuration(cf.Performance.CommitTimeout); err == nil {
			config.CommitTimeout = d
		}
	}
	if cf.Performance.SnapshotInterval != "" {
		if d, err := time.ParseDuration(cf.Performance.SnapshotInterval); err == nil {
			config.SnapshotInterval = d
		}
	}
	if cf.Performance.SnapshotThreshold > 0 {
		config.SnapshotThreshold = cf.Performance.SnapshotThreshold
	}
	if cf.Performance.MaxAppendEntries > 0 {
		config.MaxAppendEntries = cf.Performance.MaxAppendEntries
	}
	if cf.Performance.TrailingLogs > 0 {
		config.TrailingLogs = cf.Performance.TrailingLogs
	}
	
	// Initial Peers
	for _, peer := range cf.InitialPeers {
		config.InitialPeers = append(config.InitialPeers, PeerConfig{
			ID:      peer.ID,
			Address: peer.Address,
		})
	}
	
	return config, policy, nil
}

// SaveConfigToYAML은 설정을 YAML 파일로 저장
func SaveConfigToYAML(filename string, config *RaftConfig, policy *ReplicationPolicy) error {
	cf := &ConfigFile{}
	
	// Config to ConfigFile
	cf.Node.ID = config.NodeID
	cf.Node.BindAddr = config.BindAddr
	cf.Node.DataDir = config.DataDir
	cf.Node.Bootstrap = config.Bootstrap
	
	cf.Replication.Enabled = config.ReplicationEnabled
	cf.Replication.Factor = config.ReplicationFactor
	cf.Replication.MinReplicas = config.MinReplicas
	cf.Replication.Mode = string(policy.Mode)
	cf.Replication.Consistency = policy.ConsistencyLevel
	cf.Replication.TimeoutMs = policy.TimeoutMs
	cf.Replication.RetryAttempts = policy.RetryAttempts
	cf.Replication.RetryBackoffMs = policy.RetryBackoffMs
	
	cf.Performance.HeartbeatTimeout = config.HeartbeatTimeout.String()
	cf.Performance.ElectionTimeout = config.ElectionTimeout.String()
	cf.Performance.CommitTimeout = config.CommitTimeout.String()
	cf.Performance.SnapshotInterval = config.SnapshotInterval.String()
	cf.Performance.SnapshotThreshold = config.SnapshotThreshold
	cf.Performance.MaxAppendEntries = config.MaxAppendEntries
	cf.Performance.TrailingLogs = config.TrailingLogs
	
	for _, peer := range config.InitialPeers {
		cf.InitialPeers = append(cf.InitialPeers, struct {
			ID      string `yaml:"id" json:"id"`
			Address string `yaml:"address" json:"address"`
		}{
			ID:      peer.ID,
			Address: peer.Address,
		})
	}
	
	data, err := yaml.Marshal(cf)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %v", err)
	}
	
	return ioutil.WriteFile(filename, data, 0644)
}

// SaveConfigToJSON은 설정을 JSON 파일로 저장
func SaveConfigToJSON(filename string, config *RaftConfig, policy *ReplicationPolicy) error {
	cf := &ConfigFile{}
	
	// Config to ConfigFile (동일한 로직)
	cf.Node.ID = config.NodeID
	cf.Node.BindAddr = config.BindAddr
	cf.Node.DataDir = config.DataDir
	cf.Node.Bootstrap = config.Bootstrap
	
	cf.Replication.Enabled = config.ReplicationEnabled
	cf.Replication.Factor = config.ReplicationFactor
	cf.Replication.MinReplicas = config.MinReplicas
	cf.Replication.Mode = string(policy.Mode)
	cf.Replication.Consistency = policy.ConsistencyLevel
	cf.Replication.TimeoutMs = policy.TimeoutMs
	cf.Replication.RetryAttempts = policy.RetryAttempts
	cf.Replication.RetryBackoffMs = policy.RetryBackoffMs
	
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}
	
	return ioutil.WriteFile(filename, data, 0644)
}
