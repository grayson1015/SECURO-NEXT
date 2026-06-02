# Roblox PC Checker

Portable read-only Windows scanner focused on Roblox process interaction evidence.

## Build

Run:

```powershell
.\build.ps1
```

The executable will be created in:

```txt
dist\RobloxPCChecker\RobloxPCChecker.exe
```

## Usage

```powershell
RobloxPCChecker.exe --api-base-url https://your-vercel-app.vercel.app --days 7
RobloxPCChecker.exe --local-only --days 7
RobloxPCChecker.exe --html-only
RobloxPCChecker.exe --json-only
RobloxPCChecker.exe --portable --no-color --verbose
```

For the Securo website PIN flow, set `api_base_url` in `config.json`, set the `SECURO_API_BASE_URL`
environment variable, or pass `--api-base-url`. Use your deployed website URL, for example
`https://securo-next.vercel.app/`. The tool verifies the PIN before scanning,
keeps local reports even if upload fails, and uploads only the JSON report summary.

The JSON report uses the website schema:

```txt
scanTime, hostname, highestResult, confidence, evidenceSources, timeline, sessions, findings, limitations
```

The scanner never reports a PC as clean just because no injector was found. It reports:

```txt
No confirmed Roblox injection evidence was found in available logs.
Logging coverage may not be sufficient to rule it out.
```
