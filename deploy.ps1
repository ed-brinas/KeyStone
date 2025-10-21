# -----------------------------------------------------------------------------
# KeyStone API Deployment Script
# -----------------------------------------------------------------------------
# Description:
# This script automates the setup of the KeyStone Laravel API project for
# Active Directory management on a Windows environment.
#
# Prerequisites:
# - PHP (with required extensions for Laravel)
# - Composer
# - Git
#
# Usage:
# 1. Place this script in your desired projects directory.
# 2. Open a PowerShell terminal.
# 3. Run the script: .\deploy.ps1
# -----------------------------------------------------------------------------

# --- Configuration ---
$ProjectName = "."

# --- Functions ---
function Write-Host-Status($message) {
    Write-Host "✅ $($message)" -ForegroundColor Green
}

function Write-Host-Command($command) {
    Write-Host "🚀 Running: $($command)" -ForegroundColor Cyan
    $startTime = Get-Date
    Invoke-Expression $command
    $endTime = Get-Date
    $duration = New-TimeSpan -Start $startTime -End $endTime
    Write-Host "  > Command completed in $($duration.TotalSeconds) seconds."
}

function Create-File($filePath, $fileContent) {
    $fullPath = Join-Path $ProjectName $filePath
    $directory = Split-Path $fullPath -Parent
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }
    Set-Content -Path $fullPath -Value $fileContent -Encoding UTF8
    Write-Host-Status "Created/Updated file: $fullPath"
}


Write-Host "--- Starting KeyStone API Setup ---" -ForegroundColor Yellow
Write-Host-Status "Installing required composer packages..."
Write-Host-Command "composer require directorytree/ldaprecord-laravel"
Write-Host-Command "composer require laravel/sanctum"
Write-Host-Command "composer require spatie/laravel-permission"
Write-Host-Command "composer require darkaonline/l5-swagger"
Write-Host-Status "Publishing vendor configuration and assets..."
Write-Host-Command "php artisan vendor:publish --provider=`"LdapRecord\Laravel\LdapRecordServiceProvider`""
Write-Host-Command "php artisan vendor:publish --provider=`"Laravel\Sanctum\SanctumServiceProvider`""
Write-Host-Command "php artisan vendor:publish --provider=`"Spatie\Permission\PermissionServiceProvider`""
Write-Host-Command "php artisan vendor:publish --provider=`"L5Swagger\L5SwaggerServiceProvider`""
Write-Host-Status "Generating core application components with Artisan..."
Write-Host-Command "php artisan make:model AdUser -m" # For local user mapping
Write-Host-Command "php artisan make:controller AuthController"
Write-Host-Command "php artisan make:controller UserController"
Write-Host-Command "php artisan make:controller PasswordController"
Write-Host-Command "php artisan make:request LoginRequest"
Write-Host-Command "php artisan make:request CreateUserRequest"
Write-Host-Command "php artisan make:request UpdateUserRequest"
Write-Host-Command "php artisan make:request UserActionRequest"
Write-Host-Command "php artisan make:seeder RolesAndPermissionsSeeder"
Write-Host-Command "php artisan config:clear"
Write-Host-Command "php artisan key:generate"
New-Item -ItemType File -Path "database/database.sqlite" -Force | Out-Null
Write-Host-Command "php artisan migrate --seed"

