# Exemplos em PowerShell

Esta página traz exemplos prontos em PowerShell para integrar com a Sheep API.

Pré-requisitos:

* PowerShell 7 ou superior. Os exemplos também rodam em Windows PowerShell 5.1 com pequenas adaptações.

Configure o token na variável de ambiente `SHEEP_API_TOKEN`. Em produção, prefira o gerenciador de segredos da sua plataforma.

```powershell
$env:SHEEP_API_TOKEN = "shp_API_KEY_AQUI"
```

## Conversação livre

```powershell
$Token = $env:SHEEP_API_TOKEN
$Headers = @{
  "X-Sheep-Token" = $Token
  "Content-Type"  = "application/json"
}
$Body = @{
  question = "Liste IOCs tipicos de Cobalt Strike."
  model    = "hunter"
} | ConvertTo-Json -Compress

try {
  $Response = Invoke-RestMethod `
    -Uri "https://sheep.byfranke.com/api/ai/ask" `
    -Method Post `
    -Headers $Headers `
    -Body $Body `
    -TimeoutSec 45

  Write-Output $Response.response
  Write-Output ("Tier: {0}, custo: {1} tokens" -f $Response.served_by, $Response.tokens_used)
}
catch {
  $Err = $_.ErrorDetails.Message | ConvertFrom-Json
  Write-Error ("API {0}: {1}" -f $Err.detail.error, $Err.detail.message)
  exit 1
}
```

## Análise de IOC

```powershell
$Body = @{
  target = "CVE-2024-3094"
  type   = "cve"
} | ConvertTo-Json -Compress

$Result = Invoke-RestMethod `
  -Uri "https://sheep.byfranke.com/api/ai/analyze" `
  -Method Post `
  -Headers $Headers `
  -Body $Body `
  -TimeoutSec 45

Write-Output ("Veredito: {0}" -f $Result.structured_analysis.verdict)
Write-Output ("Confianca: {0}" -f $Result.structured_analysis.confidence)
Write-Output ("Custo: {0} tokens" -f $Result.structured.tokens_used)
```

## Verificar saldo

```powershell
$Profile = Invoke-RestMethod `
  -Uri "https://sheep.byfranke.com/api/profile" `
  -Headers @{ "X-Sheep-Token" = $env:SHEEP_API_TOKEN } `
  -TimeoutSec 15

Write-Output ("Plano: {0}" -f $Profile.plan.name)
Write-Output ("Restante: {0} tokens" -f $Profile.usage.tokens_remaining)
```

## Tratar 429 com Retry-After

`Invoke-RestMethod` lança exceção em códigos diferentes de 2xx. Para ler o header `Retry-After`, use `Invoke-WebRequest` ou capture a exceção.

```powershell
function Invoke-SheepAsk {
  param([string]$Question, [string]$Model = "auto")

  $Body = @{ question = $Question; model = $Model } | ConvertTo-Json -Compress
  $Headers = @{
    "X-Sheep-Token" = $env:SHEEP_API_TOKEN
    "Content-Type"  = "application/json"
  }

  for ($i = 0; $i -lt 3; $i++) {
    try {
      return Invoke-RestMethod `
        -Uri "https://sheep.byfranke.com/api/ai/ask" `
        -Method Post -Headers $Headers -Body $Body -TimeoutSec 45
    }
    catch [System.Net.WebException] {
      $Code = [int]$_.Exception.Response.StatusCode
      if ($Code -eq 429) {
        $RetryAfter = [int]$_.Exception.Response.Headers["Retry-After"]
        if ($RetryAfter -le 0) { $RetryAfter = 10 }
        Start-Sleep -Seconds $RetryAfter
        continue
      }
      if ($Code -ge 500) {
        Start-Sleep -Seconds ([math]::Pow(2, $i))
        continue
      }
      throw
    }
  }
  throw "Falha apos 3 tentativas"
}
```
