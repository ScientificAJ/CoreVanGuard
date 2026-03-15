param(
  [string]$SolutionPath = "kernel/windows/CoreVanguardMiniFilter.sln",
  [string]$Configuration = "Release",
  [string]$Platform = "x64"
)

if (-not (Test-Path $SolutionPath)) {
  Write-Host "No WDK solution checked in yet. Skipping Windows driver build."
  exit 0
}

nuget restore $SolutionPath
msbuild $SolutionPath /p:Configuration=$Configuration /p:Platform=$Platform /m

