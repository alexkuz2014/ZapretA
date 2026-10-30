param(
    [Parameter(Position = 0)]
    [string] $Message
)

$ErrorActionPreference = 'Stop'

$gitCommand = Get-Command git -ErrorAction SilentlyContinue
if ($gitCommand) {
    $git = $gitCommand.Source
} else {
    $candidates = @(
        'C:\Program Files\Git\cmd\git.exe',
        'C:\Program Files\Git\bin\git.exe'
    )
    $git = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

if (-not $git) {
    throw 'Git не найден. Установите Git for Windows и откройте новый PowerShell.'
}

function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]] $GitArgs)
    & $git @GitArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Команда git завершилась с кодом $LASTEXITCODE"
    }
}

$root = (& $git -C $PSScriptRoot rev-parse --show-toplevel 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $root) {
    throw 'Папка скрипта не находится внутри Git-репозитория.'
}

$branch = (& $git -C $root branch --show-current)
if ($LASTEXITCODE -ne 0 -or -not $branch) {
    throw 'Не удалось определить текущую ветку.'
}

$remotes = @(& $git -C $root remote)
if ($LASTEXITCODE -ne 0 -or $remotes -notcontains 'origin') {
    throw 'Удалённый репозиторий origin не настроен.'
}

& $git -C $root add -A
if ($LASTEXITCODE -ne 0) { throw 'Не удалось добавить изменения в индекс.' }

$files = @(& $git -C $root diff --cached --name-only)
if ($LASTEXITCODE -ne 0) { throw 'Не удалось прочитать список изменений.' }
if ($files.Count -eq 0) {
    Write-Host 'Изменений для отправки нет.'
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Message)) {
    $labels = @($files | ForEach-Object { Split-Path -Leaf $_ } | Select-Object -Unique)
    if ($labels.Count -le 3) {
        $summary = $labels -join ', '
    } else {
        $summary = "$($labels[0]), $($labels[1]) и ещё $($labels.Count - 2)"
    }
    $Message = "chore: обновить $summary"
}

Write-Host "Коммит: $Message"
Write-Host ($files | ForEach-Object { "  $_" })
Invoke-Git -C $root commit -m $Message
Invoke-Git -C $root push -u origin $branch
Write-Host "Готово: ветка '$branch' отправлена в origin."
