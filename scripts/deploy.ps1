param(
  [ValidateSet("up", "down", "reset", "status", "logs")]
  [string]$Action = "up"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ComposeFile = Join-Path $ProjectRoot "infrastructure/docker/compose.deploy.yml"
$EnvFile = Join-Path $ProjectRoot ".env.deploy"

function Write-PidInfo([string]$Message) {
  Write-Host "[PID] $Message" -ForegroundColor Cyan
}

function New-Secret {
  return ([Guid]::NewGuid().ToString("N") + [Guid]::NewGuid().ToString("N")).Substring(0, 48)
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-PidInfo "Installing Docker Desktop..."
    winget install --exact --id Docker.DockerDesktop --accept-package-agreements --accept-source-agreements
    throw "Docker Desktop was installed. Start it once, then rerun this command."
  }

  throw "Docker Desktop is required. Install it from https://www.docker.com/products/docker-desktop/"
}

docker info *> $null
if ($LASTEXITCODE -ne 0) {
  throw "Docker Desktop is not running. Start Docker Desktop and rerun this command."
}

docker compose version *> $null
if ($LASTEXITCODE -ne 0) {
  throw "Docker Compose v2 is required."
}

if (-not (Test-Path $EnvFile) -and $Action -eq "up") {
  $PublicHost = if ($env:PID_PUBLIC_HOST) { $env:PID_PUBLIC_HOST } else { "localhost" }
  $WebPort = if ($env:PID_WEB_PORT) { $env:PID_WEB_PORT } else { "3000" }
  $ApiPort = if ($env:PID_API_PORT) { $env:PID_API_PORT } else { "4000" }

  @"
POSTGRES_DB=unosecur_pid
POSTGRES_USER=unosecur_pid
POSTGRES_PASSWORD=$(New-Secret)
POSTGRES_PORT=5432

REDIS_PASSWORD=$(New-Secret)
REDIS_PORT=6379

NEO4J_USER=neo4j
NEO4J_PASSWORD=$(New-Secret)
NEO4J_HTTP_PORT=7474
NEO4J_BOLT_PORT=7687

API_PORT=$ApiPort
WEB_PORT=$WebPort
PUBLIC_API_URL=http://${PublicHost}:${ApiPort}/api
WEB_ORIGIN=http://${PublicHost}:${WebPort}

OLLAMA_BASE_URL=http://host.docker.internal:11434
OLLAMA_MODEL=qwen3:4b
"@ | Set-Content -Path $EnvFile -Encoding utf8

  Write-PidInfo "Created private deployment configuration at .env.deploy."
}

if (-not (Test-Path $EnvFile)) {
  throw ".env.deploy does not exist. Run .\scripts\deploy.ps1 up first."
}

$DeployConfig = @{}
Get-Content $EnvFile | ForEach-Object {
  if ($_ -match "^\s*([^#][^=]*)=(.*)$") {
    $DeployConfig[$matches[1].Trim()] = $matches[2].Trim()
  }
}
$WebPort = if ($DeployConfig["WEB_PORT"]) { $DeployConfig["WEB_PORT"] } else { "3000" }
$ApiPort = if ($DeployConfig["API_PORT"]) { $DeployConfig["API_PORT"] } else { "4000" }

$Compose = @("compose", "--env-file", $EnvFile, "-f", $ComposeFile)

switch ($Action) {
  "up" {
    Write-PidInfo "Building images and starting the complete PID stack..."
    & docker @Compose up --detach --build --wait
    if ($LASTEXITCODE -ne 0) { throw "Deployment failed." }
    Write-Host ""
    Write-Host "UnoSecur PID is running." -ForegroundColor Green
    Write-Host "  Dashboard:      http://localhost:$WebPort"
    Write-Host "  API:            http://localhost:$ApiPort/api"
    Write-Host "  Swagger:        http://localhost:$ApiPort/docs"
  }
  "down" {
    & docker @Compose down
  }
  "reset" {
    & docker @Compose down --volumes
  }
  "status" {
    & docker @Compose ps
  }
  "logs" {
    & docker @Compose logs --follow --tail=200
  }
}
