# Usage: powershell -ExecutionPolicy Bypass -File .\sheep-ask.ps1 -Token <token> -Question <question>

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Token,

    [Parameter(Mandatory=$true, Position=1, ValueFromRemainingArguments=$true)]
    [string[]]$Question
)

$ErrorActionPreference = "Stop"

$ApiUrl = "https://sheep.byfranke.com/api/ai/ask"
$QuestionText = $Question -join " "

$Body = @{
    question = $QuestionText
} | ConvertTo-Json

try {
    $Response = Invoke-RestMethod -Uri $ApiUrl `
        -Method Post `
        -ContentType "application/json" `
        -Headers @{ "X-API-Token" = $Token } `
        -Body $Body

    if ($Response.success) {
        Write-Output $Response.response
    } else {
        $ErrorMsg = if ($Response.error) { $Response.error } else { "Unknown error" }
        Write-Error "Error: $ErrorMsg"
        exit 1
    }
} catch {
    Write-Error "Error: Invalid API response - $_"
    exit 1
}
