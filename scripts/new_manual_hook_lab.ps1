[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Destination
)

$ErrorActionPreference = 'Stop'

# Create a new lab only; never overwrite, delete, move, or execute demo source.
if (-not [System.IO.Path]::IsPathRooted($Destination)) {
    throw 'Destination must be an absolute path.'
}
$labRoot = [System.IO.Path]::GetFullPath($Destination)
if (Test-Path -LiteralPath $labRoot) {
    throw 'Destination already exists. Choose a new directory; existing labs are preserved.'
}
$ancestor = [System.IO.DirectoryInfo]::new($labRoot)
while ($null -ne $ancestor) {
    if (Test-Path -LiteralPath $ancestor.FullName) {
        $item = Get-Item -LiteralPath $ancestor.FullName -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Destination must not pass through a link or junction.'
        }
        if (-not $item.PSIsContainer) {
            throw 'Destination parent must be a directory.'
        }
    }
    $ancestor = $ancestor.Parent
}
$null = Get-Command git -ErrorAction Stop
$caseFile = Join-Path $PSScriptRoot '..\samples\manual-hook-lab\cases.json'
$caseBook = Get-Content -LiteralPath $caseFile -Raw -Encoding UTF8 | ConvertFrom-Json
if ($caseBook.schema_version -ne 1) {
    throw 'Unsupported manual lab case version.'
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
New-Item -ItemType Directory -Path $labRoot | Out-Null
foreach ($project in $caseBook.projects) {
    if ($project.language -notin @('java', 'python', 'javascript', 'typescript')) {
        throw 'Unexpected project language.'
    }
    $projectRoot = Join-Path $labRoot $project.language
    New-Item -ItemType Directory -Path $projectRoot | Out-Null
    $templateRoot = Join-Path $projectRoot '.lab'
    $emptyHooks = Join-Path $templateRoot 'empty-hooks'
    New-Item -ItemType Directory -Path $emptyHooks -Force | Out-Null
    $ignoreText = @('.lab/', '.security-runtime/', '.env*', '.venv/', 'node_modules/', '__pycache__/', '') -join [Environment]::NewLine
    [System.IO.File]::WriteAllText((Join-Path $projectRoot '.gitignore'), $ignoreText, $utf8)
    $index = @(("# " + $project.language + " manual Hook lab"), "",
        "Static demonstrations only. Do not start services, install project dependencies, or execute the demo files.",
        "", "Safe versions are committed. Ignored .lab templates contain safe and risky variants.", "",
        "| Case | Target | Risky template | Expected rule |", "| --- | --- | --- | --- |")
    foreach ($case in $project.cases) {
        if ($case.id -notmatch '^0[12]$' -or $case.file -notmatch '^src/[A-Za-z_][A-Za-z0-9_]*\.(java|py|js|ts)$') {
            throw 'Unexpected case path.'
        }
        $sourcePath = Join-Path $projectRoot $case.file
        New-Item -ItemType Directory -Path (Split-Path -Parent $sourcePath) -Force | Out-Null
        [System.IO.File]::WriteAllText($sourcePath, [string]$case.safe, $utf8)
        [System.IO.File]::WriteAllText((Join-Path $templateRoot ("case-" + $case.id + ".safe.txt")), [string]$case.safe, $utf8)
        [System.IO.File]::WriteAllText((Join-Path $templateRoot ("case-" + $case.id + ".risky.txt")), [string]$case.risky, $utf8)
        $index += "| $($case.id) | $($case.file) | .lab/case-$($case.id).risky.txt | $($case.expected_rule) |"
    }
    [System.IO.File]::WriteAllText((Join-Path $projectRoot 'CASE_INDEX.md'), ($index -join [Environment]::NewLine) + [Environment]::NewLine, $utf8)
    & git -C $projectRoot init --initial-branch=main
    if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize the new lab Git repository.' }
    & git -C $projectRoot add --all
    if ($LASTEXITCODE -ne 0) { throw 'Cannot stage the new safe baseline.' }
    $commitArgs = @('-C', $projectRoot, '-c', ("core.hooksPath=" + $emptyHooks),
        '-c', 'commit.gpgSign=false', '-c', 'user.name=ManualHookLab',
        '-c', 'user.email=manual-lab@example.invalid', 'commit', '--quiet',
        '-m', 'Safe baseline for manual Hook testing')
    & git @commitArgs
    if ($LASTEXITCODE -ne 0) { throw 'Cannot commit the new safe baseline.' }
    Write-Output $projectRoot
}

