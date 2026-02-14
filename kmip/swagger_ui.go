package kmip

// SwaggerUIHTML은 Swagger UI HTML 페이지
const SwaggerUIHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KMIP REST API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.10.0/swagger-ui.css">
    <link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAA7AAAAOwBeShxvQAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAKGSURBVFiFvZdPaBNBFMa/N5vdJE2bGKwHRRARPHgQxIMHD4IgCIIgCB48eBAEQRAEQfDgwYMgCIIgCILgwYMHQRAEQRAEQRAE/4AHQRAEwT9gY9Jks7uzu/M8ZDfZTZrEP/CDhZ15897Hezuzb4B/lKIoSjzP84qi6P+CqqpKJpNRFUX5v6AoipJKpZR/AQghRCKR+CeAqqoKIcS/AURE0zRNCCH+FBARAQCmaZqKooh/AYiIaJqmCQD+rwAxTdP0fd/3PC+SHce5VSqVXs7Pz1+dnJy8Njs7ezOTydxIJpO3oyyvVqvdLxaLT0ql0svp6emrMzMz15LJ5N1YLHa/VqvdLxQKjyuVyqtSqfRienr6SjqdvpZIJO4lEokH5XL5YaVSeVYul59OTU1dmpiYuBqPxx8mEonHlUrlWblcfjI5OXk5Ho8/isfj/wAQRdGFpmnT8zxvdnZ2fnFx8XJzc/N5t9s9Go/Hn7RarbOtra33nU7nsNfrvW+325tLS0tX2+32RqfTOWy1WmetVut9p9M5aDQaH1qt1odut/upVqudNhqNz71e71O32/1Yq9VO6/X650aj8bHT6Xzodrsn1Wr1pNFofOp0OgfVavWkXq9/rNfrJ5VK5XO1Wj2pVCqnlUrlc6VS+VytVk8qlcqXSqXytVKpfC2Xy98qlcq3SqXyrVKpfCuXy98rlcr3crn8o1wuf6tUKj8qlcqPcrl8Ui6Xf5bL5Z/lcvlnuVw+KZfLP8vl8kmxWP5RLBZ/FovFn8Vi8UexWPxRKBR+FQqFX4VC4VehUPhVKBR+5fP534VC4Xc+n/+dz+d/5/P53/l8/nc+n/+Vy+V+53K537lc7ncul/uVy+V+5XK5X9ls7k8ul/udzeZ+Z7O5P9ls7k82m/uTyeT+ZDK5P5lM7k8mk/udzeb/ZLO5v9ls/m8mk/+byeT/plKpv6lU6m8ymdQSiYSmaZr2F8BWNZ/cXb3UAAAAAElFTkSuQmCC">
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        }
        
        .topbar {
            background-color: #2d3748;
            padding: 10px 0;
        }
        
        .topbar-wrapper {
            max-width: 1460px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .topbar-wrapper .link {
            display: flex;
            align-items: center;
        }
        
        .topbar-wrapper .link img {
            height: 40px;
            margin-right: 10px;
        }
        
        .topbar-wrapper .link span {
            color: #fff;
            font-size: 20px;
            font-weight: 600;
        }
        
        .swagger-ui .topbar {
            display: none;
        }
        
        .custom-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .custom-header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 700;
        }
        
        .custom-header p {
            margin: 10px 0 0 0;
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .info-section {
            max-width: 1200px;
            margin: 30px auto;
            padding: 0 20px;
        }
        
        .info-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .info-card {
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .info-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        
        .info-card h3 {
            margin: 0 0 10px 0;
            color: #2d3748;
            font-size: 1.1em;
        }
        
        .info-card p {
            margin: 0;
            color: #718096;
            line-height: 1.6;
        }
        
        .info-card .stat {
            font-size: 2em;
            font-weight: 700;
            color: #667eea;
            margin: 10px 0;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
            margin-right: 5px;
        }
        
        .badge-success {
            background: #48bb78;
            color: white;
        }
        
        .badge-info {
            background: #4299e1;
            color: white;
        }
        
        .badge-warning {
            background: #ed8936;
            color: white;
        }
        
        .swagger-section {
            max-width: 1460px;
            margin: 0 auto;
        }
    </style>
</head>
<body>
    <div class="topbar">
        <div class="topbar-wrapper">
            <div class="link">
                <span>🔐 KMIP Server</span>
            </div>
            <div>
                <span style="color: #a0aec0; font-size: 14px;">Version 1.0.0</span>
            </div>
        </div>
    </div>

    <div class="custom-header">
        <h1>KMIP REST API Documentation</h1>
        <p>Key Management Interoperability Protocol - RESTful Interface</p>
    </div>

    <div class="info-section">
        <div class="info-cards">
            <div class="info-card">
                <h3>🔑 Key Operations</h3>
                <div class="stat">15+</div>
                <p>Comprehensive key lifecycle management including create, register, retrieve, and delete operations</p>
            </div>
            
            <div class="info-card">
                <h3>🔐 Security</h3>
                <div class="stat">100%</div>
                <p>TLS encryption, input validation, SQL injection & XSS prevention, rate limiting</p>
            </div>
            
            <div class="info-card">
                <h3>🌐 Replication</h3>
                <div class="stat">Multi-DC</div>
                <p>Cross-cluster replication with Raft consensus for high availability</p>
            </div>
            
            <div class="info-card">
                <h3>📊 KMIP Versions</h3>
                <div class="stat">1.0 - 3.0</div>
                <p>Support for KMIP 1.0, 1.1, 1.2, 1.3, 1.4, 2.0, 2.1, and 3.0</p>
            </div>
        </div>

        <div class="info-card">
            <h3>Supported Features</h3>
            <p style="margin-top: 15px;">
                <span class="badge badge-success">Symmetric Keys</span>
                <span class="badge badge-success">Asymmetric Keys</span>
                <span class="badge badge-success">Key Pairs</span>
                <span class="badge badge-info">Attributes</span>
                <span class="badge badge-info">Search</span>
                <span class="badge badge-info">Rekey</span>
                <span class="badge badge-warning">Raft Replication</span>
                <span class="badge badge-warning">Cross-Cluster</span>
            </p>
        </div>
    </div>

    <div class="swagger-section" id="swagger-ui"></div>

    <script src="https://unpkg.com/swagger-ui-dist@5.10.0/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.10.0/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/api/v1/swagger.yaml',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                defaultModelsExpandDepth: 1,
                defaultModelExpandDepth: 1,
                docExpansion: 'list',
                filter: true,
                showRequestHeaders: true,
                showCommonExtensions: true,
                tryItOutEnabled: true,
                requestInterceptor: (request) => {
                    // Add custom headers if needed
                    return request;
                },
                onComplete: () => {
                    console.log('Swagger UI loaded successfully');
                }
            });

            window.ui = ui;
        };
    </script>
</body>
</html>
`
