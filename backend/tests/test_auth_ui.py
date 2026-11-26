from pathlib import Path


FRONTEND = Path(__file__).resolve().parents[2] / "frontend" / "index.html"


def _html() -> str:
    return FRONTEND.read_text(encoding="utf-8")


def test_login_and_signup_forms_remain_available():
    html = _html()
    assert 'id="authForm"' in html
    assert 'id="authEmail"' in html
    assert 'id="authPassword"' in html
    assert 'id="authSwitch"' in html
    assert '/auth/${signup ? "signup" : "login"}' in html


def test_password_visibility_controls_cover_password_and_confirmation():
    html = _html()
    assert 'data-password-target="authPassword"' in html
    assert 'data-password-target="authConfirmPassword"' in html
    assert 'aria-pressed="false"' in html
    assert 'button.textContent = showing ? "Hide" : "Show"' in html


def test_auth_form_has_accessible_labels_and_live_error_region():
    html = _html()
    assert 'aria-labelledby="authTitle"' in html
    assert 'aria-live="polite"' in html
    assert 'aria-label="Show password"' in html
    assert 'for="authConfirmPassword"' in html


def test_auth_only_ui_has_responsive_styling_and_signup_password_guidance():
    html = _html()
    assert ".auth-overlay" in html
    assert "@media(max-width:480px)" in html
    assert "Use at least 12 characters." in html
    assert "prefers-reduced-motion:reduce" in html


def test_password_recovery_and_verification_ui_hooks_exist():
    html = _html()
    assert 'id="authForgot"' in html
    assert 'id="recoveryPanel"' in html
    assert 'id="resendVerification"' in html
    assert 'id="recoveryAction"' in html
    assert '/auth/password-reset/request' in html
    assert '/auth/password-reset/confirm' in html
    assert '/auth/verify-email' in html
    assert 'processAuthLink()' in html


def test_account_drawer_and_company_subscription_summary_ui_exist():
    html = _html()
    assert 'id="accountButton"' in html
    assert 'id="accountDrawer"' in html
    assert 'openAccountPanel()' in html
    assert '/api/v1/account/summary' in html
    assert 'SQL analyses' in html
    assert 'Company workspace' in html
    assert 'Next renewal' in html

def test_frontend_uses_same_origin_api_when_served_by_fastapi():
    html = _html()
    assert 'window.location.origin' in html
    assert '"5500", "5501"' in html

def test_local_setup_enables_login_and_development_verification():
    root = FRONTEND.parents[1]
    setup = root / "setup-local.ps1"
    config = root / "backend" / "app" / "config.py"
    assert setup.exists()
    assert "DATALINEAGE_AUTH_ENABLED=true" in setup.read_text(encoding="utf-8")
    assert "DATALINEAGE_EMAIL_DEV_MODE=true" in setup.read_text(encoding="utf-8")
    assert "load_dotenv" in config.read_text(encoding="utf-8")


def test_account_action_is_in_topbar_and_not_in_left_rail():
    html = _html()
    topbar = html.split('<div class="topbar-actions">', 1)[1].split('</div>', 1)[0]
    assert 'id="accountButton"' in topbar
    assert 'id="githubImpactToggle"' in topbar
    assert '<nav class="app-side-rail"' not in html


def test_github_impact_panel_is_collapsible_below_topbar():
    html = _html()
    topbar_end = html.index('</div>', html.index('<div class="topbar-actions">'))
    panel_start = html.index('id="githubIntegrationPanel"')
    stats_start = html.index('<div class="stats">')
    assert topbar_end < panel_start < stats_start
    assert 'id="githubIntegrationPanel" hidden' in html
    assert 'aria-expanded="false"' in html
    assert 'function toggleGitHubImpactPanel()' in html
    assert 'panel.scrollIntoView' in html
    assert 'ghLoadRepositories()' in html
    assert 'ghLoadPullRequests()' in html
    assert 'ghAnalyzeLivePR()' in html
