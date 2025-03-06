# Define the log file path
$LogFile = "C:\Temp\script_log.txt"
New-Item -Path $LogFile -ItemType File -Force | Out-Null

# Function to Log Output to File
function Log-Output {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$Timestamp - $Message"
}

# Ensure the script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Log-Output "Script was not running with elevated privileges. Restarting as admin."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-File `"$PSCommandPath`"" -Verb RunAs -Wait
    exit
}
Log-Output "Script is running with elevated privileges."

# Function to Write Output with Color
function Write-ColorOutput {
    param ([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor ([System.ConsoleColor]::$Color)
    Log-Output $Message
}

# Function to Uninstall OneDrive
function Uninstall-OneDrive {
    Write-ColorOutput "Uninstalling OneDrive..." "Yellow"
    Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
    
    foreach ($Path in @("$env:SystemRoot\System32\OneDriveSetup.exe", "$env:SystemRoot\SysWOW64\OneDriveSetup.exe")) {
        if (Test-Path $Path) {
            Start-Process -FilePath $Path -ArgumentList "/uninstall" -NoNewWindow -Wait
            Log-Output "OneDrive uninstalled from $Path."
        }
    }
    Write-ColorOutput "OneDrive has been uninstalled." "Green"
}

# Function to Configure Lock Screen Settings
function Configure-LockScreen {
    Write-ColorOutput "Configuring Lock Screen settings..." "Yellow"
    $RegistryPaths = @(
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Slideshow",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"
    )
    
    foreach ($Path in $RegistryPaths) {
        if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    }
    
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen" -Name "SlideshowEnabled" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Slideshow" -Name "IsEnabled" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Slideshow" -Name "FolderPath" -Value "C:\Windows\Web\Screen" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0 -ErrorAction SilentlyContinue
    
    Write-ColorOutput "Lock Screen settings configured." "Green"
}

# Function to Configure Taskbar Settings
function Configure-Taskbar {
    Write-ColorOutput "Configuring Taskbar settings..." "Yellow"
    
    # Modify HKCU (User-Level) Taskbar Settings
    $ExplorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    if (!(Test-Path $ExplorerPath)) { New-Item -Path $ExplorerPath -Force | Out-Null }
    
    try {
        Set-ItemProperty -Path $ExplorerPath -Name "ShowTaskViewButton" -Value 0
        Write-ColorOutput "Successfully configured Taskbar settings in HKCU." "Green"
    } catch {
        Write-ColorOutput "Failed to configure Taskbar settings in HKCU: $_" "Red"
    }

    # Modify HKLM (System-Level) Taskbar Settings with Invoke-Command
    $ScriptBlock = {
        param ($RegistryKey)
        Start-Process -FilePath "powershell.exe" -ArgumentList "-Command `"Set-ItemProperty -Path $RegistryKey -Name 'TaskbarDa' -Value 0 -Force`"" -Verb RunAs -Wait
    }
    
    try {
        Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Write-ColorOutput "Successfully configured TaskbarDa in HKLM." "Green"
    } catch {
        Write-ColorOutput "Failed to configure TaskbarDa in HKLM: $_" "Red"
    }
}

# Function to Remove Bloatware Applications
function Remove-Bloatware {
    Write-ColorOutput "Removing bloatware applications..." "Yellow"
    $BloatwareApps = @(
        "B9ECED6F.ASUSPCAssistant", "ICEpower.AudioWizard", "Microsoft.BingWeather",
        "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.Microsoft3DViewer",
        "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.MicrosoftStickyNotes", "Microsoft.MixedReality.Portal",
        "Microsoft.Office.OneNote", "Microsoft.ScreenSketch", "Microsoft.SkypeApp",
        "Microsoft.Wallet", "Microsoft.WindowsAlarms", "microsoft.windowscommunicationsapps",
        "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", "Microsoft.WindowsSoundRecorder",
        "Microsoft.Xbox.TCUI", "Microsoft.XboxApp", "Microsoft.XboxGameOverlay",
        "Microsoft.XboxGamingOverlay", "Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay", "Microsoft.YourPhone", "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo", "AppUp.IntelGraphicsExperience"
    )
    
    foreach ($App in $BloatwareApps) {
        try {
            Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
            Write-ColorOutput "Removed: $App" "Green"
        } catch {
            Write-ColorOutput "Failed to remove: $App" "Red"
        }
    }
    Write-ColorOutput "Bloatware removal completed." "Green"
}

# Main script execution
try {
    Uninstall-OneDrive
    Configure-LockScreen
    Configure-Taskbar
    Remove-Bloatware
    Log-Output "Script execution completed."
} catch {
    Write-ColorOutput "An error occurred: $_" "Red"
    Log-Output "Error: $_"
}

# Keep the PowerShell window open
Read-Host "Press Enter to exit"
