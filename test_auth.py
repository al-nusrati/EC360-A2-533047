"""
test_auth.py - Unit tests for auth_service.py (Jira Story QM-5)
Run with:  python -m unittest -v test_auth
"""
import unittest

from auth_service import AuthService, hash_password, verify_password, TOKEN_TTL_SECONDS


class FakeClock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


class TestPasswordHashing(unittest.TestCase):
    def test_hash_is_salted_and_not_plaintext(self):
        h1, h2 = hash_password("Secret123"), hash_password("Secret123")
        self.assertNotIn("Secret123", h1)
        self.assertNotEqual(h1, h2)          # different random salts

    def test_verify_password(self):
        stored = hash_password("Secret123")
        self.assertTrue(verify_password("Secret123", stored))
        self.assertFalse(verify_password("secret123", stored))


class TestRegistrationWorkflow(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.svc = AuthService(clock=self.clock)

    def test_valid_registration_returns_201_and_queues_email(self):
        status, body = self.svc.register("Ali@Example.com", "Secret123")
        self.assertEqual(status, 201)
        self.assertEqual(body["status"], "pending_verification")
        self.assertEqual(len(self.svc.outbox), 1)
        self.assertEqual(self.svc.outbox[0]["to"], "ali@example.com")

    def test_duplicate_email_returns_409(self):
        self.svc.register("ali@example.com", "Secret123")
        status, body = self.svc.register("ALI@example.com", "Other456A")
        self.assertEqual((status, body["error"]), (409, "email_already_registered"))

    def test_invalid_email_returns_422(self):
        status, body = self.svc.register("not-an-email", "Secret123")
        self.assertEqual((status, body["error"]), (422, "invalid_email"))

    def test_weak_password_returns_422(self):
        status, body = self.svc.register("ali@example.com", "short")
        self.assertEqual((status, body["error"]), (422, "weak_password"))

    def test_unverified_user_cannot_login(self):
        self.svc.register("ali@example.com", "Secret123")
        status, _ = self.svc.login("ali@example.com", "Secret123")
        self.assertEqual(status, 403)

    def test_verification_then_login_succeeds(self):
        self.svc.register("ali@example.com", "Secret123")
        token = self.svc.outbox[0]["token"]
        self.assertEqual(self.svc.verify_email(token)[0], 200)
        self.assertEqual(self.svc.login("ali@example.com", "Secret123")[0], 200)

    def test_token_is_single_use(self):
        self.svc.register("ali@example.com", "Secret123")
        token = self.svc.outbox[0]["token"]
        self.svc.verify_email(token)
        self.assertEqual(self.svc.verify_email(token)[0], 400)

    def test_expired_token_returns_410(self):
        self.svc.register("ali@example.com", "Secret123")
        token = self.svc.outbox[0]["token"]
        self.clock.now += TOKEN_TTL_SECONDS + 1
        self.assertEqual(self.svc.verify_email(token)[0], 410)

    def test_wrong_password_returns_401(self):
        self.svc.register("ali@example.com", "Secret123")
        self.assertEqual(self.svc.login("ali@example.com", "Wrong999X")[0], 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
