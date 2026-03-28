# Development Server Launcher for Windows PowerShell
# Automatically starts all services for Zein Security WAF

$ErrorActionPreference = "Continue"

# Colors
function Write-ColorLog {
    param(
        [string]$Service,
        [string]$Message,
        [string]$Color = "White"
    )
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] [$Service] " -NoNewline
    Write-Host $Message -ForegroundColor $Color
}

Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║         Zein Security WAF - Development Server              ║
║         Starting all services...                             ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Check prerequisites
Write-ColorLog "SYSTEM" "Checking prerequisites..." "Cyan"

$hasDocker = $null -ne (Get-Command docker -ErrorAction SilentlyContinue)
$hasGo = $null -ne (Get-Command go -ErrorAction SilentlyContinue)
$hasPython = $null -ne (Get-Command python -ErrorAction SilentlyContinue)
$hasNode = $null -ne (Get-Command node -ErrorAction SilentlyContinue)

if (-not $hasNode) {
    Write-ColorLog "SYSTEM" "Node.js is required but not found!" "Red"
    exit 1
}

if (-not $hasGo) {
    Write-ColorLog "SYSTEM" "Go is required for the backend but not found!" "Red"
    Write-ColorLog "SYSTEM" "Please install Go from https://golang.org/dl/" "Yellow"
}

if (-not $hasPython) {
    Write-ColorLog "SYSTEM" "Python is required for the AI service but not found!" "Red"
    Write-ColorLog "SYSTEM" "Please install Python from https://www.python.org/downloads/" "Yellow"
}

# Start Docker services if available
if ($hasDocker) {
    Write-ColorLog "DOCKER" "Starting PostgreSQL and Redis..." "Blue"
    Set-Location $PSScriptRoot\..
    docker-compose up -d postgres redis
    if ($LASTEXITCODE -eq 0) {
        Write-ColorLog "DOCKER" "Database services started successfully!" "Green"
        Start-Sleep -Seconds 5
    } else {
        Write-ColorLog "DOCKER" "Docker services may already be running" "Yellow"
        Start-Sleep -Seconds 2
    }
} else {
    Write-ColorLog "SYSTEM" "Docker not found. Make sure PostgreSQL and Redis are running locally." "Yellow"
}

# Start all services
Write-ColorLog "SYSTEM" "Starting application services..." "Cyan"

$jobs = @()

# Start AI Service
if ($hasPython) {
    Write-ColorLog "AI-SERVICE" "Starting AI Service..." "Green"
    Set-Location $PSScriptRoot\..\backend\ai-service
    $aiJob = Start-Job -ScriptBlock {
        Set-Location $using:PWD
        python -m uvicorn ai:app --host 0.0.0.0 --port 5000 --reload
    }
    $jobs += $aiJob
    Set-Location $PSScriptRoot\..
    Start-Sleep -Seconds 2
    Write-ColorLog "AI-SERVICE" "AI Service is running" "Green"
} else {
    Write-ColorLog "AI-SERVICE" "Skipped (Python not found)" "Yellow"
}

# Start Backend
if ($hasGo) {
    Write-ColorLog "BACKEND" "Starting Backend..." "Yellow"
    Set-Location $PSScriptRoot\..\backend
    $backendJob = Start-Job -ScriptBlock {
        Set-Location $using:PWD
        go run main.go
    }
    $jobs += $backendJob
    Set-Location $PSScriptRoot\..
    Start-Sleep -Seconds 2
    Write-ColorLog "BACKEND" "Backend is running" "Green"
} else {
    Write-ColorLog "BACKEND" "Skipped (Go not found)" "Yellow"
}

# Start Frontend
Write-ColorLog "FRONTEND" "Starting Frontend..." "Magenta"
Set-Location $PSScriptRoot\..\frontend
$frontendJob = Start-Job -ScriptBlock {
    Set-Location $using:PWD
    npm run dev
}
$jobs += $frontendJob
Set-Location $PSScriptRoot\..

Write-ColorLog "SYSTEM" "All services started! Press Ctrl+C to stop." "Green"
Write-ColorLog "SYSTEM" "Frontend: http://localhost:3000" "Cyan"
Write-ColorLog "SYSTEM" "Backend API: http://localhost:8080" "Cyan"
Write-ColorLog "SYSTEM" "AI Service: http://localhost:5000" "Cyan"

# Handle graceful shutdown
$null = Register-EngineEvent PowerShell.Exiting -Action {
    Write-Host "`nShutting down all services..." -ForegroundColor Yellow
    $jobs | ForEach-Object { Stop-Job $_; Remove-Job $_ }
    if ($hasDocker) {
        Set-Location $PSScriptRoot\..
        docker-compose stop postgres redis
    }
}

# Wait for user interrupt
try {
    while ($true) {
        Start-Sleep -Seconds 1
        # Check if jobs are still running
        $runningJobs = $jobs | Where-Object { $_.State -eq "Running" }
        if ($runningJobs.Count -eq 0) {
            Write-ColorLog "SYSTEM" "All services stopped." "Yellow"
            break
        }
    }
} catch {
    Write-ColorLog "SYSTEM" "Shutting down..." "Yellow"
} finally {
    $jobs | ForEach-Object { Stop-Job $_; Remove-Job $_ }
    if ($hasDocker) {
        Set-Location $PSScriptRoot\..
        docker-compose stop postgres redis
    }
}







