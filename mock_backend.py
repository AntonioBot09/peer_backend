#!/usr/bin/env python3
"""
Minimal Mock Backend for Security Testing
Simulates PeerNetwork GraphQL API endpoints for testing
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import re
from urllib.parse import urlparse, parse_qs
import threading
import time

class MockBackendHandler(BaseHTTPRequestHandler):
    """HTTP handler that simulates GraphQL API responses"""
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok'}).encode())
        elif self.path == '/graphql':
            # GraphQL via GET (not typical but possible)
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'error': 'GraphQL queries must use POST'
            }).encode())
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'error': 'Not found'
            }).encode())
    
    def do_POST(self):
        """Handle POST requests (GraphQL API)"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8'))
            query = data.get('query', '')
            variables = data.get('variables', {})
            
            # Process GraphQL query
            response = self.process_graphql(query, variables)
            
            self.send_response(response['status'])
            self.send_header('Content-Type', 'application/json')
            
            # Add rate limit headers if applicable
            if 'rate_limit' in response:
                self.send_header('X-RateLimit-Limit', '100')
                self.send_header('X-RateLimit-Remaining', '95')
                self.send_header('X-RateLimit-Reset', str(int(time.time()) + 3600))
            
            self.end_headers()
            self.wfile.write(json.dumps(response['body']).encode())
            
        except json.JSONDecodeError:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'error': 'Invalid JSON'
            }).encode())
    
    def process_graphql(self, query: str, variables: dict) -> dict:
        """Process GraphQL query and return response"""
        
        # Check for SQL injection attempts
        sql_patterns = [
            r"'.*OR.*'1'='1",
            r"'.*UNION.*SELECT",
            r"'.*DROP.*TABLE",
            r"'.*SLEEP\(",
            r"'.*--",
            r"'.*#",
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return {
                    'status': 400,
                    'body': {'error': 'Invalid input detected'},
                    'rate_limit': True
                }
        
        # Check for XSS attempts
        xss_patterns = [
            r"<script[^>]*>",
            r"on\w+\s*=",
            r"javascript:",
            r"alert\(",
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return {
                    'status': 400,
                    'body': {'error': 'Invalid input detected'},
                    'rate_limit': True
                }
        
        # Parse query type
        if 'mutation Login' in query:
            return self.handle_login(query, variables)
        elif 'mutation Register' in query:
            return self.handle_register(query, variables)
        elif 'mutation Contactus' in query:
            return self.handle_contactus(query, variables)
        elif 'query' in query:
            return self.handle_query(query, variables)
        else:
            return {
                'status': 400,
                'body': {'error': 'Invalid GraphQL query'},
                'rate_limit': False
            }
    
    def handle_login(self, query: str, variables: dict) -> dict:
        """Handle login mutation"""
        # Extract email and password from query
        email_match = re.search(r'email:\s*"([^"]+)"', query)
        password_match = re.search(r'password:\s*"([^"]+)"', query)
        
        if not email_match or not password_match:
            return {
                'status': 400,
                'body': {'error': 'Missing email or password'},
                'rate_limit': False
            }
        
        email = email_match.group(1)
        password = password_match.group(1)
        
        # Simulate authentication
        if email == 'test@example.com' and password == 'Password123!':
            return {
                'status': 200,
                'body': {
                    'data': {
                        'login': {
                            'meta': {
                                'status': 'success',
                                'RequestId': 'req_123',
                                'ResponseCode': '200',
                                'ResponseMessage': 'Login successful'
                            },
                            'accessToken': 'mock_jwt_token_123',
                            'refreshToken': 'mock_refresh_token_123'
                        }
                    }
                },
                'rate_limit': True
            }
        else:
            return {
                'status': 401,
                'body': {
                    'data': {
                        'login': {
                            'meta': {
                                'status': 'error',
                                'RequestId': 'req_124',
                                'ResponseCode': '401',
                                'ResponseMessage': 'Invalid credentials'
                            },
                            'accessToken': None,
                            'refreshToken': None
                        }
                    }
                },
                'rate_limit': True
            }
    
    def handle_register(self, query: str, variables: dict) -> dict:
        """Handle register mutation"""
        # Check for required fields
        required_fields = ['email', 'password', 'username']
        for field in required_fields:
            if f'{field}:' not in query:
                return {
                    'status': 400,
                    'body': {'error': f'Missing required field: {field}'},
                    'rate_limit': False
                }
        
        # Simulate successful registration
        return {
            'status': 200,
            'body': {
                'data': {
                    'register': {
                        'meta': {
                            'status': 'success',
                            'RequestId': 'req_125',
                            'ResponseCode': '200',
                            'ResponseMessage': 'Registration successful'
                        },
                        'userid': 'user_123'
                    }
                }
            },
            'rate_limit': True
        }
    
    def handle_contactus(self, query: str, variables: dict) -> dict:
        """Handle contactus mutation"""
        required_fields = ['name', 'email', 'message']
        for field in required_fields:
            if f'{field}:' not in query:
                return {
                    'status': 400,
                    'body': {'error': f'Missing required field: {field}'},
                    'rate_limit': False
                }
        
        # Simulate successful contact form submission
        return {
            'status': 200,
            'body': {
                'data': {
                    'contactus': {
                        'meta': {
                            'status': 'success',
                            'RequestId': 'req_126',
                            'ResponseCode': '200',
                            'ResponseMessage': 'Message sent successfully'
                        },
                        'affectedRows': [{
                            'msgid': 'msg_123',
                            'email': 'extracted@example.com',
                            'name': 'Extracted Name',
                            'message': 'Extracted message',
                            'ip': '127.0.0.1',
                            'createdat': '2026-04-09T16:45:00Z'
                        }]
                    }
                }
            },
            'rate_limit': True
        }
    
    def handle_query(self, query: str, variables: dict) -> dict:
        """Handle generic queries"""
        if '__typename' in query:
            return {
                'status': 200,
                'body': {
                    'data': {
                        '__typename': 'Query'
                    }
                },
                'rate_limit': False
            }
        elif '__schema' in query:
            return {
                'status': 200,
                'body': {
                    'data': {
                        '__schema': {
                            'types': [
                                {'name': 'Query'},
                                {'name': 'Mutation'},
                                {'name': 'User'},
                                {'name': 'Post'}
                            ]
                        }
                    }
                },
                'rate_limit': False
            }
        else:
            return {
                'status': 200,
                'body': {
                    'data': {}
                },
                'rate_limit': False
            }
    
    def log_message(self, format, *args):
        """Override to reduce log noise"""
        pass

class MockBackend:
    """Mock backend server"""
    
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
    
    def start(self):
        """Start the mock backend server"""
        self.server = HTTPServer((self.host, self.port), MockBackendHandler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        print(f"✅ Mock backend started at http://{self.host}:{self.port}")
        print(f"   Endpoints:")
        print(f"   - POST /graphql (GraphQL API)")
        print(f"   - GET  /health (Health check)")
        print()
    
    def stop(self):
        """Stop the mock backend server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            print("✅ Mock backend stopped")
    
    def get_url(self):
        """Get server URL"""
        return f"http://{self.host}:{self.port}"

def main():
    """Run mock backend"""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        # Quick self-test
        backend = MockBackend(port=0)  # Random port
        backend.start()
        time.sleep(2)
        
        import requests
        try:
            # Test health endpoint
            response = requests.get(f"{backend.get_url()}/health")
            print(f"Health check: {response.status_code} - {response.json()}")
            
            # Test GraphQL endpoint
            response = requests.post(
                f"{backend.get_url()}/graphql",
                json={'query': 'query { __typename }'}
            )
            print(f"GraphQL query: {response.status_code} - {response.json()}")
            
        finally:
            backend.stop()
    else:
        # Start server
        backend = MockBackend()
        backend.start()
        
        try:
            print("Mock backend running. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping...")
        finally:
            backend.stop()

if __name__ == '__main__':
    main()