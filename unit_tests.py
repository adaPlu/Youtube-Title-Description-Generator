import unittest
from unittest.mock import patch, MagicMock
from tkinter import Tk
import requests
import json


from YoutubeTitlerClient import (
    YoutubeTitleDescriptionGeneratorGUI,
    load_key,
    save_key,
    hash_password,
    verify_password,
    register_or_verify_user,
    encrypt_and_save_data,
    load_and_decrypt_data
)

class TestUtilityFunctions(unittest.TestCase):
    def test_load_key_nonexistent(self):
        with patch('os.path.exists', return_value=False), \
             patch('builtins.open', unittest.mock.mock_open()) as mocked_file:
            key = load_key()
            self.assertTrue(mocked_file.called)
            self.assertIsNotNone(key)

    def test_hash_password(self):
        password = "TestPassword123!"
        pwdhash, salt = hash_password(password)
        self.assertTrue(verify_password(pwdhash, password, salt))

class TestUserAuthentication(unittest.TestCase):
    def setUp(self):
        self.root = Tk()
        # Mock the messagebox to always return True for askyesno, simulating a user clicking "Yes"
        with patch('tkinter.messagebox.askyesno', return_value=False), \
             patch('tkinter.messagebox.showerror'), \
             patch('requests.post') as mocked_post:
            # Simulate a successful login response
            mocked_post.return_value.json.return_value = {'message': 'Login successful.'}
            mocked_post.return_value.status_code = 200
            self.gui = YoutubeTitleDescriptionGeneratorGUI(self.root)

    def test_register_user_success(self):
        with patch('requests.post') as mocked_post:
            mocked_post.return_value.json.return_value = {'message': 'Registration successful.'}
            mocked_post.return_value.status_code = 201
            success, message, username = register_or_verify_user(self.root, True)
            self.assertTrue(success)

    def test_login_user_success(self):
        with patch('requests.post') as mocked_post:
            mocked_post.return_value.json.return_value = {'message': 'Login successful.'}
            mocked_post.return_value.status_code = 200
            self.gui.user_verification()
            self.assertIsNotNone(self.gui.username)

class TestEncryption(unittest.TestCase):
    def test_encrypt_and_save_data(self):
        api_key = 'test_api_key'
        client_secrets_path = 'test_secrets.json'
        with patch('builtins.open', unittest.mock.mock_open()) as mocked_file:
            encrypt_and_save_data(api_key, client_secrets_path)
            self.assertTrue(mocked_file.called)

    def test_load_and_decrypt_data(self):
        expected_key = 'test_api_key'
        with patch('builtins.open', unittest.mock.mock_open(read_data=json.dumps({
            "api_key": base64.urlsafe_b64encode(expected_key.encode()).decode(),
            "client_secrets_path": ""
        }))), \
             patch('cryptography.fernet.Fernet.decrypt', return_value=expected_key.encode()):
            api_key, _ = load_and_decrypt_data()
            self.assertEqual(api_key, expected_key)

if __name__ == '__main__':
    unittest.main()
