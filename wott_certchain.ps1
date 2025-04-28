param([String]$url="")

$WebRequest = [Net.WebRequest]::CreateHttp($url)
$WebRequest.AllowAutoRedirect = $true
$chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

try {$Response = $WebRequest.GetResponse()}
catch {}

$Certificate = $WebRequest.ServicePoint.Certificate.Handle
$Issuer = $WebRequest.ServicePoint.Certificate.Issuer
$Subject = $WebRequest.ServicePoint.Certificate.Subject

$chain.Build($Certificate)
write-host $chain.ChainElements.Count
write-host $chain.ChainElements[0].Certificate.IssuerName.Name

[Net.ServicePointManager]::ServerCertificateValidationCallback = $null

write-host $chain.ChainElements.Certificate
