from fastapi.testclient import TestClient
from apps.api.main import app

client = TestClient(app)

def test_auth_me_initial():
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 200
    data = response.json()
    assert data["authenticated"] is True
    assert "user" in data

def test_google_oauth_and_onboarding_flow():
    # 1. Google OAuth Sign-In (new user requires onboarding)
    payload = {
        "token": "g-oauth-test-token-12345",
        "profile": {
            "name": "Sarah Connor",
            "email": "sarah.connor@cyberdyne-defense.org",
            "avatar_url": "https://images.unsplash.com/photo-1534528741775-53994a69daeb"
        }
    }
    resp = client.post("/api/v1/auth/google", json=payload)
    assert resp.status_code == 200
    auth_data = resp.json()
    assert auth_data["status"] == "success"
    assert "token" in auth_data
    assert auth_data["needs_onboarding"] is True
    uid = auth_data["user"]["id"]

    # 2. Complete Onboarding Wizard with Tailored Settings
    onboard_payload = {
        "user_id": uid,
        "name": "Sarah Connor",
        "organization": "Cyberdyne Special Ops",
        "role": "Lead Reverse Engineer",
        "suspicion_threshold": 0.40,
        "malicious_threshold": 0.70,
        "wl_depth": 4,
        "target_architecture": "x86_64",
        "focus_motifs": ["Ransomware Traversal", "Packed UPX & CFF"]
    }
    resp = client.post("/api/v1/auth/onboarding", json=onboard_payload)
    assert resp.status_code == 200
    ob_data = resp.json()
    assert ob_data["status"] == "success"
    assert ob_data["user"]["onboarded"] is True
    assert ob_data["user"]["organization"] == "Cyberdyne Special Ops"
    assert ob_data["user"]["suspicion_threshold"] == 0.40

    # 3. Notification Generated for Onboarding
    resp = client.get("/api/v1/notifications")
    assert resp.status_code == 200
    notifs = resp.json()
    items = notifs.get("items", notifs)
    assert len(items) >= 1
    assert any("Onboarding Complete" in n["title"] for n in items)

def test_notifications_lifecycle():
    # Read all notifications
    resp = client.post("/api/v1/notifications/mark-all-read")
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"

    # Verify 0 unread
    resp = client.get("/api/v1/notifications")
    assert resp.status_code == 200
    data = resp.json()
    assert data["unread"] == 0

    # Clear notifications
    resp = client.delete("/api/v1/notifications")
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"

    # Verify empty
    resp = client.get("/api/v1/notifications")
    data = resp.json()
    items = data.get("items", data)
    assert len(items) == 0

def test_google_auth_config():
    resp = client.get("/api/v1/auth/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "google_client_id" in data
    assert len(data["google_client_id"]) > 0

def test_settings_lifecycle():
    # 1. Fetch current settings
    resp = client.get("/api/v1/settings")
    assert resp.status_code == 200
    s = resp.json()
    assert s["status"] == "success"
    assert "backend_engine" in s

    # 2. Update settings
    update_payload = {
        "name": "Commander Shepard",
        "email": "shepard@normandy-soc.io",
        "organization": "Systems Alliance Defense",
        "role": "Lead Reverse Engineer",
        "suspicion_threshold": 0.42,
        "malicious_threshold": 0.78,
        "wl_depth": 4,
        "target_architecture": "arm64",
        "fusion_alpha": 0.65,
        "air_gapped": True,
        "zero_false_positive_bias": True,
        "focus_motifs": ["Ransomware Traversal", "Dynamic API Resolvers"]
    }
    resp = client.post("/api/v1/settings", json=update_payload)
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["status"] == "success"
    assert updated["settings"]["suspicion_threshold"] == 0.42
    assert updated["settings"]["malicious_threshold"] == 0.78
    assert updated["settings"]["target_architecture"] == "arm64"

    # 3. Reset settings
    resp = client.post("/api/v1/settings/reset")
    assert resp.status_code == 200
    reset_data = resp.json()
    assert reset_data["status"] == "success"
    assert reset_data["settings"]["suspicion_threshold"] == 0.45
    assert reset_data["settings"]["malicious_threshold"] == 0.75
