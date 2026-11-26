# EC360-A2 - QuickCart
Microservices

EC360 Software Engineering, Assignment 2 (individual): Agile Scrum lifecycle, Git feature-branch workflow and Jira + GitHub integration.

| Field | Value |
|---|---|
| Author | Jawad Ahmed |
| Student ID | 533047 |
| Class | DE-46 (B), Fall 2026 |
| Department | Computer & Software Engineering, CEME, NUST |
| Jira project | QuickCart Microservices (key `QM`) |

## Contents

- `auth_service.py`: authentication service for story **QM-5** (customer registration with email verification). It has the registration endpoint, salted PBKDF2-HMAC-SHA256 password hashing and single-use verification tokens that expire.
- `test_auth.py`: unit and workflow tests for the registration flow.

## Run the tests

```
python -m unittest -v test_auth
```

## Branching model

Feature-branch workflow. Each story gets its own branch (`feature/QM-<n>-<slug>`). Every commit message starts with its Jira key, and branches are merged into `main` with `--no-ff`, so every merge node stays visible in the history.
