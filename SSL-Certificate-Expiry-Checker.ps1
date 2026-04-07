<#
.SYNOPSIS
    SSL Certificate Expiry Checker

.DESCRIPTION
    Scans SSL certificates across a list of servers or hostnames, checks expiry
    dates, and sends an email alert for any certificates expiring within a
    defined threshold (default: 30 days). Exports results to a timestamped CSV.

.AUTHOR
    Dayana Ann V M

.VERSION
    1.0

.NOTES
    Requirements:
    - Network access to target servers on port 443
    - SMTP server access for email alerts
    - PowerShell 5.1 or later
#>

# -----------------------------------------------
# CONFIGURATION
# -----------------------------------------------
$Servers = @(
    "server1.yourdomain.com",
    "server2.yourdomain.com",
    "netscaler-vpx.yourdomain.com"
    # Add more hostnames as needed
)

$Port              = 443
$ExpiryThresholdDays = 30
$LogDirectory      = "C:\Logs\SSLCertCheck"
$SMTPServer        = "smtp.yourdomain.com"
$SMTPPort          = 25
$AlertFrom         = "ssl-monitor@yourdomain.com"
$AlertTo           = "infra-team@yourdomain.com"
$AlertSubject      = "SSL Certificate Expiry Alert - $(Get-Date -Format 'yyyy-MM-dd')"

# -----------------------------------------------
# INITIALISE
# -----------------------------------------------
$Timestamp  = Get-Date -Format "yyyyMMdd_HHmm"
$LogFile    = "$LogDirectory\SSLCertCheck_$Timestamp.csv"
$Results    = @()
$SendAlert  = $false
$AlertBody  = ""

if (-not (Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory | Out-Null
}

# -----------------------------------------------
# CHECK CERTIFICATES
# -----------------------------------------------
foreach ($Server in $Servers) {
    Write-Host "[INFO] Checking certificate on: $Server" -ForegroundColor Cyan

    try {
        $TCPClient  = New-Object System.Net.Sockets.TcpClient($Server, $Port)
        $SSLStream  = New-Object System.Net.Security.SslStream($TCPClient.GetStream(), $false,
            ({ $true } -as [System.Net.Security.RemoteCertificateValidationCallback]))
        $SSLStream.AuthenticateAsClient($Server)
        $Cert       = $SSLStream.RemoteCertificate
        $X509       = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Cert)

        $ExpiryDate  = $X509.NotAfter
        $DaysLeft    = ($ExpiryDate - (Get-Date)).Days
        $Status      = if ($DaysLeft -le $ExpiryThresholdDays) { "EXPIRING SOON" } else { "OK" }

        if ($Status -eq "EXPIRING SOON") {
            $SendAlert  = $true
            $AlertBody += "[EXPIRING SOON] $Server | Expires: $ExpiryDate | Days Left: $DaysLeft`n"
            Write-Host "[EXPIRING SOON] $Server | Expires: $ExpiryDate | Days Left: $DaysLeft" -ForegroundColor Red
        } else {
            Write-Host "[OK] $Server | Expires: $ExpiryDate | Days Left: $DaysLeft" -ForegroundColor Green
        }

        $Results += [PSCustomObject]@{
            Server      = $Server
            Subject     = $X509.Subject
            Issuer      = $X509.Issuer
            ExpiryDate  = $ExpiryDate
            DaysLeft    = $DaysLeft
            Status      = $Status
            Thumbprint  = $X509.Thumbprint
            CheckedAt   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }

        $SSLStream.Close()
        $TCPClient.Close()

    } catch {
        Write-Warning "[WARNING] Could not connect to $Server — $_"
        $Results += [PSCustomObject]@{
            Server      = $Server
            Subject     = "N/A"
            Issuer      = "N/A"
            ExpiryDate  = "N/A"
            DaysLeft    = "N/A"
            Status      = "CONNECTION FAILED"
            Thumbprint  = "N/A"
            CheckedAt   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
}

# -----------------------------------------------
# EXPORT CSV
# -----------------------------------------------
$Results | Export-Csv -Path $LogFile -NoTypeInformation -Encoding UTF8
Write-Host "[INFO] Report exported: $LogFile"

# -----------------------------------------------
# EMAIL ALERT
# -----------------------------------------------
if ($SendAlert) {
    $Body = @"
SSL Certificate Expiry Alert
==============================
Date/Time  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Threshold  : $ExpiryThresholdDays days

Certificates Expiring Soon:
----------------------------
$AlertBody

Full report attached.
"@

    try {
        Send-MailMessage `
            -From $AlertFrom `
            -To $AlertTo `
            -Subject $AlertSubject `
            -Body $Body `
            -SmtpServer $SMTPServer `
            -Port $SMTPPort `
            -Attachments $LogFile

        Write-Host "[INFO] Alert sent to $AlertTo" -ForegroundColor Yellow
    } catch {
        Write-Error "[ERROR] Failed to send email: $_"
    }
} else {
    Write-Host "[INFO] All certificates are healthy. No alert sent." -ForegroundColor Green
}
