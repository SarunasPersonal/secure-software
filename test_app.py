import unittest
import json
import os
import tempfile
import sqlite3
from app import app, init_db

class AppTestCase(unittest.TestCase):
    def setUp(self):
        # Create a temporary file for the test database
        self.db_fd, app.config['DATABASE'] = tempfile.mkstemp()
        app.config['TESTING'] = True
        self.client = app.test_client()
        
        # Initialize the database
        init_db()
        
        # Clear any existing data to ensure a clean test environment
        conn = sqlite3.connect(app.config['DATABASE'])
        conn.execute("DELETE FROM users")
        conn.execute("DELETE FROM notes")
        conn.commit()
        conn.close()

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(app.config['DATABASE'])

    def test_register_valid_user(self):
        response = self.client.post(
            '/register',
            data=json.dumps({
                'username': 'testuser',
                'password': 'TestPassword123!'
            }),
            content_type='application/json'
        )
        data = json.loads(response.data)
        print(f"Register response: {response.status_code}, {data}")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(data['message'], 'User registered successfully')
        self.assertIn('token', data)

    def test_register_invalid_username(self):
        response = self.client.post(
            '/register',
            data=json.dumps({
                'username': 'te',  # Too short
                'password': 'TestPassword123!'
            }),
            content_type='application/json'
        )
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 400)
        self.assertIn('Invalid username format', data['message'])

    def test_register_weak_password(self):
        response = self.client.post(
            '/register',
            data=json.dumps({
                'username': 'testuser',
                'password': 'password'  # Weak password
            }),
            content_type='application/json'
        )
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 400)
        self.assertIn('Password does not meet security requirements', data['message'])

    def test_login_success(self):
        # First register a user
        self.client.post(
            '/register',
            data=json.dumps({
                'username': 'loginuser',
                'password': 'LoginPass123!'
            }),
            content_type='application/json'
        )
        
        # Then try to login
        response = self.client.post(
            '/login',
            data=json.dumps({
                'username': 'loginuser',
                'password': 'LoginPass123!'
            }),
            content_type='application/json'
        )
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['message'], 'Login successful')
        self.assertIn('token', data)

    def test_login_invalid_credentials(self):
        response = self.client.post(
            '/login',
            data=json.dumps({
                'username': 'nonexistent',
                'password': 'WrongPass123!'
            }),
            content_type='application/json'
        )
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(data['message'], 'Invalid credentials')

    def test_create_note_without_auth(self):
        response = self.client.post(
            '/notes',
            data=json.dumps({
                'title': 'Test Note',
                'content': 'This is a test note'
            }),
            content_type='application/json'
        )
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(data['message'], 'Token is missing!')

    def test_create_and_get_note_with_auth(self):
        # Register a user
        register_response = self.client.post(
            '/register',
            data=json.dumps({
                'username': 'noteuser',
                'password': 'NotePass123!'
            }),
            content_type='application/json'
        )
        register_data = json.loads(register_response.data)
        print(f"Register response in test_create_and_get_note_with_auth: {register_response.status_code}, {register_data}")
        self.assertIn('token', register_data, "Token missing in registration response")
        token = register_data['token']
        
        # Create a note
        create_response = self.client.post(
            '/notes',
            data=json.dumps({
                'title': 'Test Note',
                'content': 'This is a test note'
            }),
            content_type='application/json',
            headers={'x-access-token': token}
        )
        create_data = json.loads(create_response.data)
        self.assertEqual(create_response.status_code, 201)
        self.assertEqual(create_data['message'], 'Note created successfully')
        
        # Get notes
        get_response = self.client.get(
            '/notes',
            headers={'x-access-token': token}
        )
        get_data = json.loads(get_response.data)
        self.assertEqual(get_response.status_code, 200)
        self.assertEqual(len(get_data['notes']), 1)
        self.assertEqual(get_data['notes'][0]['title'], 'Test Note')
        self.assertEqual(get_data['notes'][0]['content'], 'This is a test note')

    def test_xss_prevention(self):
        # Register a user
        register_response = self.client.post(
            '/register',
            data=json.dumps({
                'username': 'xssuser',
                'password': 'XssPass123!'
            }),
            content_type='application/json'
        )
        register_data = json.loads(register_response.data)
        print(f"Register response in test_xss_prevention: {register_response.status_code}, {register_data}")
        self.assertIn('token', register_data, "Token missing in registration response")
        token = register_data['token']
        
        # Create a note with XSS payload
        xss_title = '<script>alert("XSS");</script>'
        xss_content = '<img src="x" onerror="alert(\'XSS\')">'
        
        create_response = self.client.post(
            '/notes',
            data=json.dumps({
                'title': xss_title,
                'content': xss_content
            }),
            content_type='application/json',
            headers={'x-access-token': token}
        )
        
        # Get notes
        get_response = self.client.get(
            '/notes',
            headers={'x-access-token': token}
        )
        get_data = json.loads(get_response.data)
        
        # Check that XSS payloads were escaped
        self.assertNotEqual(get_data['notes'][0]['title'], xss_title)
        self.assertNotEqual(get_data['notes'][0]['content'], xss_content)
        self.assertEqual(get_data['notes'][0]['title'], '&lt;script&gt;alert(&quot;XSS&quot;);&lt;/script&gt;')
        self.assertEqual(get_data['notes'][0]['content'], '&lt;img src=&quot;x&quot; onerror=&quot;alert(&#x27;XSS&#x27;)&quot;&gt;')

if __name__ == '__main__':
    unittest.main()