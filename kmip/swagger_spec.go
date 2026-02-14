package kmip

// OpenAPISpec은 KMIP REST API의 OpenAPI 3.0 스펙
const OpenAPISpec = `
openapi: 3.0.3
info:
  title: KMIP REST API
  description: |
    KMIP (Key Management Interoperability Protocol) REST API Server
    
    ## Features
    - Symmetric and Asymmetric key management
    - Key lifecycle operations (Create, Register, Retrieve, Delete, Rekey)
    - Attribute management (Add, Modify, Delete)
    - Advanced search with filters
    - Cross-cluster replication
    - Raft-based distributed storage
    
    ## Security
    - TLS encryption
    - Input validation
    - SQL Injection prevention
    - XSS prevention
    - Rate limiting
    
  version: 1.0.0
  contact:
    name: API Support
    email: support@example.com
  license:
    name: Apache 2.0
    url: https://www.apache.org/licenses/LICENSE-2.0.html

servers:
  - url: http://localhost:9090
    description: Development server
  - url: https://api.example.com
    description: Production server

tags:
  - name: Keys
    description: Key management operations
  - name: KeyPairs
    description: Asymmetric key pair operations
  - name: Attributes
    description: Key attribute management
  - name: Search
    description: Key search and discovery
  - name: Server
    description: Server information
  - name: Replication
    description: Cross-cluster replication

paths:
  /health:
    get:
      summary: Health check
      description: Check if the server is healthy
      tags:
        - Server
      responses:
        '200':
          description: Server is healthy
          content:
            application/json:
              schema:
                type: object
                properties:
                  status:
                    type: string
                    example: healthy
                  timestamp:
                    type: string
                    format: date-time

  /api/v1/server/info:
    get:
      summary: Get server information
      description: Retrieve server version, capabilities, and configuration
      tags:
        - Server
      responses:
        '200':
          description: Server information
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ServerInfo'

  /api/v1/server/versions:
    get:
      summary: Get supported KMIP versions
      description: List all supported KMIP protocol versions
      tags:
        - Server
      responses:
        '200':
          description: Supported versions
          content:
            application/json:
              schema:
                type: object
                properties:
                  versions:
                    type: array
                    items:
                      type: string
                    example: ["1.0", "1.1", "1.2", "2.0", "3.0"]

  /api/v1/keys:
    get:
      summary: List all keys
      description: Retrieve a list of all managed keys
      tags:
        - Keys
      parameters:
        - name: limit
          in: query
          description: Maximum number of keys to return
          schema:
            type: integer
            minimum: 1
            maximum: 1000
            default: 100
        - name: offset
          in: query
          description: Number of keys to skip
          schema:
            type: integer
            minimum: 0
            default: 0
      responses:
        '200':
          description: List of keys
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/KeyList'

    post:
      summary: Create a new key
      description: Create a new symmetric or asymmetric key
      tags:
        - Keys
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateKeyRequest'
            examples:
              AES-256:
                summary: Create AES-256 key
                value:
                  algorithm: AES
                  length: 256
                  attributes:
                    environment: production
                    owner: john.doe
              RSA-2048:
                summary: Create RSA-2048 key pair
                value:
                  algorithm: RSA
                  length: 2048
                  attributes:
                    purpose: signing
      responses:
        '201':
          description: Key created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CreateKeyResponse'
        '400':
          description: Invalid request
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'

  /api/v1/keys/{keyId}:
    get:
      summary: Get key by ID
      description: Retrieve a specific key by its unique identifier
      tags:
        - Keys
      parameters:
        - $ref: '#/components/parameters/KeyId'
      responses:
        '200':
          description: Key details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Key'
        '404':
          description: Key not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'

    delete:
      summary: Delete key
      description: Delete a key permanently
      tags:
        - Keys
      parameters:
        - $ref: '#/components/parameters/KeyId'
      responses:
        '200':
          description: Key deleted successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Key deleted successfully
        '404':
          description: Key not found

  /api/v1/keypairs:
    post:
      summary: Create key pair
      description: Create a new asymmetric key pair (RSA, ECDSA, etc.)
      tags:
        - KeyPairs
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateKeyPairRequest'
            examples:
              RSA-2048:
                summary: RSA-2048 key pair
                value:
                  algorithm: RSA
                  length: 2048
              ECDSA-256:
                summary: ECDSA P-256 key pair
                value:
                  algorithm: ECDSA
                  length: 256
      responses:
        '201':
          description: Key pair created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CreateKeyPairResponse'

  /api/v1/keys/register:
    post:
      summary: Register existing key
      description: Register an externally generated key
      tags:
        - Keys
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RegisterKeyRequest'
      responses:
        '201':
          description: Key registered successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CreateKeyResponse'
        '400':
          description: Invalid key material

  /api/v1/keys/search:
    post:
      summary: Search keys
      description: Search for keys using attribute filters
      tags:
        - Search
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/SearchRequest'
            examples:
              by-environment:
                summary: Search by environment
                value:
                  attributes:
                    environment: production
              by-alternate-name:
                summary: Search by alternate name
                value:
                  alternate_name: web-app-key
      responses:
        '200':
          description: Search results
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SearchResponse'

  /api/v1/keys/attributes/{keyId}:
    get:
      summary: Get key attributes
      description: Retrieve all attributes for a specific key
      tags:
        - Attributes
      parameters:
        - $ref: '#/components/parameters/KeyId'
      responses:
        '200':
          description: Key attributes
          content:
            application/json:
              schema:
                type: object
                properties:
                  key_id:
                    type: string
                  attributes:
                    type: object
                    additionalProperties: true

    post:
      summary: Add or modify attributes
      description: Add new attributes or modify existing ones
      tags:
        - Attributes
      parameters:
        - $ref: '#/components/parameters/KeyId'
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/AttributeRequest'
      responses:
        '200':
          description: Attributes updated
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                  key_id:
                    type: string

    delete:
      summary: Delete attribute
      description: Remove a specific attribute from a key
      tags:
        - Attributes
      parameters:
        - $ref: '#/components/parameters/KeyId'
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - attribute_name
              properties:
                attribute_name:
                  type: string
                  example: environment
      responses:
        '200':
          description: Attribute deleted

  /api/v1/keys/rekey/{keyId}:
    post:
      summary: Rekey (regenerate key)
      description: Generate a new key with the same attributes
      tags:
        - Keys
      parameters:
        - $ref: '#/components/parameters/KeyId'
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                attributes:
                  type: object
                  additionalProperties: true
      responses:
        '201':
          description: Key regenerated
          content:
            application/json:
              schema:
                type: object
                properties:
                  old_key_id:
                    type: string
                  new_key_id:
                    type: string

  /api/v1/replication/clusters:
    get:
      summary: List remote clusters
      description: Get all configured remote clusters for replication
      tags:
        - Replication
      responses:
        '200':
          description: Cluster list
          content:
            application/json:
              schema:
                type: object
                properties:
                  clusters:
                    type: array
                    items:
                      $ref: '#/components/schemas/RemoteCluster'
                  total:
                    type: integer

    post:
      summary: Add remote cluster
      description: Configure a new remote cluster for replication
      tags:
        - Replication
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RemoteClusterRequest'
      responses:
        '201':
          description: Cluster added
          content:
            application/json:
              schema:
                type: object
                properties:
                  status:
                    type: string
                  cluster_id:
                    type: string

    delete:
      summary: Remove remote cluster
      description: Remove a remote cluster configuration
      tags:
        - Replication
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - cluster_id
              properties:
                cluster_id:
                  type: string
      responses:
        '200':
          description: Cluster removed

  /api/v1/replication/status:
    get:
      summary: Get replication status
      description: Check the status of cross-cluster replication
      tags:
        - Replication
      responses:
        '200':
          description: Replication status
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ReplicationStatus'

components:
  parameters:
    KeyId:
      name: keyId
      in: path
      required: true
      description: Unique key identifier
      schema:
        type: string
        pattern: '^[a-zA-Z0-9_-]+$'
        example: 550e8400-e29b-41d4-a716-446655440000

  schemas:
    ServerInfo:
      type: object
      properties:
        version:
          type: string
          example: 1.0.0
        kmip_versions:
          type: array
          items:
            type: string
          example: ["1.0", "1.1", "2.0", "3.0"]
        features:
          type: array
          items:
            type: string
          example: ["replication", "raft", "search"]

    KeyList:
      type: object
      properties:
        keys:
          type: array
          items:
            $ref: '#/components/schemas/KeySummary'
        total:
          type: integer
          example: 42
        limit:
          type: integer
          example: 100
        offset:
          type: integer
          example: 0

    KeySummary:
      type: object
      properties:
        key_id:
          type: string
        algorithm:
          type: string
          enum: [AES, DES, 3DES, RSA, DSA, ECDSA, SEED, ARIA]
        length:
          type: integer
        created_at:
          type: string
          format: date-time
        state:
          type: string
          enum: [active, compromised, destroyed]

    Key:
      allOf:
        - $ref: '#/components/schemas/KeySummary'
        - type: object
          properties:
            key_material:
              type: string
              description: Hex-encoded key material
            attributes:
              type: object
              additionalProperties: true

    CreateKeyRequest:
      type: object
      required:
        - algorithm
        - length
      properties:
        algorithm:
          type: string
          enum: [AES, DES, 3DES, RSA, DSA, ECDSA, SEED, ARIA]
          description: Cryptographic algorithm
        length:
          type: integer
          minimum: 8
          maximum: 4096
          description: Key length in bits
        attributes:
          type: object
          additionalProperties: true
          description: Optional key attributes
          maxProperties: 100

    CreateKeyResponse:
      type: object
      properties:
        key_id:
          type: string
        status:
          type: string
          example: created

    CreateKeyPairRequest:
      type: object
      required:
        - algorithm
        - length
      properties:
        algorithm:
          type: string
          enum: [RSA, DSA, ECDSA]
        length:
          type: integer
        attributes:
          type: object
          additionalProperties: true

    CreateKeyPairResponse:
      type: object
      properties:
        public_key_id:
          type: string
        private_key_id:
          type: string
        status:
          type: string

    RegisterKeyRequest:
      type: object
      required:
        - key_type
        - key_material
        - algorithm
        - length
      properties:
        key_type:
          type: string
          enum: [symmetric, public, private]
        key_material:
          type: string
          description: Hex-encoded key material
          pattern: '^[0-9a-fA-F]+$'
        algorithm:
          type: string
        length:
          type: integer
        attributes:
          type: object
          additionalProperties: true

    SearchRequest:
      type: object
      properties:
        attributes:
          type: object
          additionalProperties: true
        alternate_name:
          type: string
          maxLength: 1024
        max_results:
          type: integer
          minimum: 1
          maximum: 1000
        offset:
          type: integer
          minimum: 0

    SearchResponse:
      type: object
      properties:
        keys:
          type: array
          items:
            $ref: '#/components/schemas/KeySummary'
        total:
          type: integer
        matched:
          type: integer

    AttributeRequest:
      type: object
      required:
        - action
        - attributes
      properties:
        action:
          type: string
          enum: [add, modify]
        attributes:
          type: object
          additionalProperties: true
          maxProperties: 100

    RemoteCluster:
      type: object
      properties:
        id:
          type: string
        name:
          type: string
        endpoints:
          type: array
          items:
            type: string
            format: uri
        enabled:
          type: boolean
        status:
          type: string
          enum: [active, failed, paused]
        last_sync:
          type: string
          format: date-time
        error_count:
          type: integer

    RemoteClusterRequest:
      type: object
      required:
        - id
        - name
        - endpoints
      properties:
        id:
          type: string
          pattern: '^[a-zA-Z0-9_-]+$'
        name:
          type: string
          maxLength: 1024
        endpoints:
          type: array
          items:
            type: string
            format: uri
          minItems: 1
          maxItems: 10
        enabled:
          type: boolean
          default: true
        priority:
          type: integer
          minimum: 1
          maximum: 100
        bidirectional:
          type: boolean
          default: false
        api_key:
          type: string
        tls_enabled:
          type: boolean

    ReplicationStatus:
      type: object
      properties:
        local_cluster:
          type: string
        clusters:
          type: array
          items:
            $ref: '#/components/schemas/RemoteCluster'
        summary:
          type: object
          properties:
            total:
              type: integer
            active:
              type: integer
            failed:
              type: integer
            errors:
              type: integer

    Error:
      type: object
      properties:
        error:
          type: string
        message:
          type: string
        details:
          type: object
          additionalProperties: true

  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
    BearerAuth:
      type: http
      scheme: bearer

security:
  - ApiKeyAuth: []
  - BearerAuth: []
`
