# Securo

Portable read-only Windows scanner focused on Roblox process interaction evidence.

## Build

Run:

```powershell
python build.py
```

The portable folder and website download ZIP will be created in:

```txt
dist\Securo\Securo.exe
dist\Securo\Tools\
public\downloads\Securo.zip
```

Put approved forensic parser helpers in `Tools\` before building if you want the portable folder to include them:

```txt
PECmd.exe
MFTECmd.exe
SBECmd.exe
JLECmd.exe
SrumECmd.exe
AmcacheParser.exe
AppCompatCacheParser.exe
```

Set `external_forensic_tools_enabled` to `true` in `config.json` to let Securo run those helpers read-only with timeouts, write CSV output to `Documents\Securo\ToolOutput`, and import that evidence into the report.

## Usage

```powershell
Securo.exe --api-base-url https://your-vercel-app.vercel.app --days 7
Securo.exe --local-only --days 7
Securo.exe --html-only
Securo.exe --json-only
Securo.exe --portable --no-color --verbose
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

## Business License

Run `supabase/schema.sql` in Supabase to add business license support.

Included business key:

```txt
SEC-MVP-V7K2-M9Q4-X3P8
```

Business keys allow up to 20 unique emails. Owners can view used slots and revoke an email slot from `/admin`.
