[CmdletBinding()]
param(
    [switch]$Detached,
    [switch]$IntegrationTest
)

$ErrorActionPreference = "Stop"
$env:COMPOSE_BAKE = "false"

Write-Host "Using Docker Compose without Bake delegation." -ForegroundColor Cyan
& docker compose version
if ($LASTEXITCODE -ne 0) {
    throw "Docker Compose v2 is unavailable. Start or update Docker Desktop and use 'docker compose', not the legacy 'docker-compose' executable."
}

if ($IntegrationTest) {
    & docker compose --profile integration-test up `
        --build `
        --abort-on-container-exit `
        --exit-code-from integration-test `
        integration-test
}
else {
    $arguments = @("compose", "up", "--build")
    if ($Detached) {
        $arguments += "--detach"
    }

    & docker @arguments
}

exit $LASTEXITCODE
