# Cache automation configuration
# Copy this to Update-Cache.config.ps1 and fill in your values

$Config = @{
    # Upstream API
    ApiUrl = "https://panel.safepass.icu/6dLihhTVbNgnftDlu0D3Q01/api/v2/admin/user/"
    ApiKey = "75626fed-a0a4-4cdf-a0f8-1985b4c5034b"
    
    # Proxy settings (required when VPN is active)
    Proxy = "http://127.0.0.1:10808"  # Used for API calls and cache generation
    
    # Local paths (relative to tools/)
    BackupFile = "data/updated_backup.json"
    CacheDir = "../apps/relay/storage/cache"
    ZipFile = "data/cache.zip"
    
    # cPanel FTP
    FtpHost = "ftp.thesafestpass.ir"
    FtpPort = 21
    FtpUser = "h352292"
    FtpPass = ""  # Leave empty to prompt, or store securely
    HostAccountUsername = "cpaneluser"
    RemotePath = "/public_html/enter"  # Override default FTP root ("/")
    FtpRetries = 3
    FtpRetryDelaySeconds = 10
    
    # Extract endpoint
    ExtractUrl = "https://enter.thesafestpass.ir/extract.php"
    ExtractToken = "change-this-secret-token"  # Must match EXTRACT_TOKEN in cache-only .env (use single quotes if token contains $)
    ExtractRetries = 3
    ExtractRetryDelaySeconds = 5

    # Optional injected messages (leave empty to disable)
    InjectPlacement = "remark"  # "remark" or "address"
    InjectMessage1 = ""  # Plain text message (save this file as UTF-8)
    InjectMessage2 = ""
}
