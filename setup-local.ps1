$ErrorActionPreference = 'Stop'
$backend = Join-Path $PSScriptRoot 'backend'
$envPath = Join-Path $backend '.env'
if (-not (Test-Path $backend)) { throw 'Could not find the backend folder.' }
if (Test-Path $envPath) {
    Write-Host 'backend\.env already exists. It was not overwritten.' -ForegroundColor Yellow
    Write-Host 'If you need to reset local authentication, back up and remove that file, then run this script again.'
    exit 0
}
$sessionSecret = (& python -c "import secrets; print(secrets.token_urlsafe(48))").Trim()
$adminPassword = (& python -c "import secrets; print(secrets.token_urlsafe(24))").Trim()
if (-not $sessionSecret -or -not $adminPassword) { throw 'Python could not generate local secrets.' }
$contents = @"
DATALINEAGE_AUTH_ENABLED=true
DATALINEAGE_AUTH_USERNAME=admin
DATALINEAGE_AUTH_PASSWORD=$adminPassword
DATALINEAGE_SESSION_SECRET=$sessionSecret
DATALINEAGE_SESSION_TTL_SECONDS=28800
DATALINEAGE_SECURE_COOKIE=false
DATALINEAGE_ENVIRONMENT=development
DATALINEAGE_EMAIL_DEV_MODE=true
DATALINEAGE_PUBLIC_BASE_URL=http://127.0.0.1:8000
DATALINEAGE_GITHUB_CREDENTIAL_KEY=
"@
Set-Content -Path $envPath -Value $contents -Encoding UTF8
Write-Host ''
Write-Host 'Local authentication is now configured.' -ForegroundColor Green
Write-Host 'Login and account creation will be enabled. New accounts use the local email-verification link shown by the app.'
Write-Host 'Local admin username: admin'
Write-Host "Local admin password: $adminPassword" -ForegroundColor Yellow
Write-Host 'Keep backend\.env private. Do not upload it to GitHub or share it.'
