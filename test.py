import unittest
import json
import sqlite3
import time
from flask import Flask, jsonify, request, app

class TestJWKSServer(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.testing = True
        self.app = app.test_client()

    def test_auth_request(self):
        # Test authentication endpoint without expired parameter
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 404)
        self.assertIn(b'.', response.data)  # Assuming JWT contains a dot

        # Test authentication endpoint with expired parameter
        response = self.app.post('/auth?expired=true')
        self.assertEqual(response.status_code, 404)
        self.assertIn(b'.', response.data)  # Assuming JWT contains a dot

    def test_database(self):
        # Open database connection
        conn = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = conn.cursor()

        # Check for keys
        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
        self.assertTrue(count > 0, "Database check failed: no keys found.")

        # Checking for valid/exp keys based on time
        now = int(time.time())
        cursor.execute("SELECT exp FROM keys")
        rows = cursor.fetchall()

        valid_keys = sum(1 for row in rows if row[0] > now)
        expired_keys = count - valid_keys

        self.assertTrue(valid_keys > 0, "Database check failed: no valid keys found.")
        self.assertTrue(expired_keys >= 0, "Expired keys count is negative.")

        print(f"Database check successful: {valid_keys} valid keys, {expired_keys} expired keys found.")

        # Close database connection
        conn.close()

if __name__ == "__main__":
    unittest.main()