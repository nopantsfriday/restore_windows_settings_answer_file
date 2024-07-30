<# Disable unnecessary log files and writes to SSD
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#>
Write-Host "Disable unnecessary log files and writes to SSD" -ForegroundColor Cyan

function create_dummyfolder_file {
  param($CheckPath)
  if ((Test-Path -LiteralPath $CheckPath) -ne $true) { 
    New-Item -Path $CheckPath -ItemType File -force -ea SilentlyContinue | Out-Null; 
    Write-Host "$CheckPath" -BackgroundColor Black -ForegroundColor Green -NoNewline; 
    Write-Host " was created." -ForegroundColor White -BackgroundColor Black 
  } 
  else { 
    Write-Host "$CheckPath" -BackgroundColor Black -ForegroundColor Yellow -NoNewline; 
    Write-Host " already exists." -ForegroundColor White -BackgroundColor Black 
  }
}

$CheckPath = '~\AppData\LocalLow\Deo VR'
create_dummyfolder_file -CheckPath $CheckPath

$CheckPath = '~\AppData\LocalLow\DeoVR'
create_dummyfolder_file -CheckPath $CheckPath

<# Install winget and software
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#>
  winget.exe install -e --id 7zip.7zip
  winget.exe install -e --id Argotronic.ArgusMonitor
  winget.exe install -e --id Discord.Discord
  winget.exe install -e --id Elgato.StreamDeck
  winget.exe install -e --id Git.Git
  winget.exe install -e --id Google.Chrome
  winget.exe install -e --id Logitech.GHUB
  winget.exe install -e --id Microsoft.Edge
  winget.exe install -e --id Microsoft.PowerShell
  winget.exe install -e --id Microsoft.VisualStudioCode
  winget.exe install -e --id Microsoft.WindowsTerminal
  winget.exe install -e --id Mozilla.Firefox
  winget.exe install -e --id Nevcairiel.LAVFilters
  winget.exe install -e --id OpenWhisperSystems.Signal
  winget.exe install -e --id Spotify.Spotify
  winget.exe install -e --id VideoLAN.VLC


# Hides the Meet Now Button on the Taskbar
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f

# Disables Bing Search in Start Menu
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f

# Disables Mouse Acceleration
reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d "0" /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d "0" /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d "0" /f

# Disables Sticky Keys
reg.exe add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d "506" /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v HotkeyFlags /t REG_SZ /d "58" /f

# Disables Snap Assist Flyout
reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v SnapAssist /t REG_DWORD /d 0 /f

# Enables Show File Extensions
reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f

# Enables Dark Mode
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f


# Restore Windows Photo Viewer and Set as Default Program for Image Files
# Restore Windows Photo Viewer
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.bmp" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.cr2" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.dib" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.gif" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.ico" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jfif" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jpe" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jpeg" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jpg" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jxr" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.png" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.tif" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.tiff" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.wdp" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
# Create Relevant File Associations
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cr2\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dib\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gif\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ico\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jfif\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpe\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpg\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jxr\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.png\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tif\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tiff\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wdp\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f

# Disables Windows Recall on Copilot+ PC - Credit Britec09
reg.exe add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI" /f
reg.exe add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Windows AI" /v "TurnOffSavingSnapshots" /t REG_DWORD /d 1 /f

# Disables Wallpaper JPEG Quality Reduction in Windows 10
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v JPEGImportQuality /t REG_DWORD /d 100 /f

# Hides and Removes News and Interests from PC and Taskbar
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f

# Disables Location Services
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v LocationServicesEnabled /t REG_DWORD /d 0 /f

# Disables Input Personalization Settings
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f

# Disables Automatic Feedback Sampling
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feedback" /v AutoSample /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feedback" /v ServiceEnabled /t REG_DWORD /d 0 /f

# Disables Recent Documents Tracking
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackDocs /t REG_DWORD /d 0 /f

# Disable "Let websites provide locally relevant content by accessing my language list"
reg.exe add "HKEY_CURRENT_USER\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f

# Disables "Let Windows track app launches to improve Start and search results"
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f

# Disables Background Apps
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f

# Disables App Diagnostics
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppDiagnostics" /v AppDiagnosticsEnabled /t REG_DWORD /d 0 /f

function create_registry_key {

    if (!(Test-Path $registryPath)) {
      New-Item -Path $registryPath -Force | Out-Null
      New-ItemProperty -Name $name -Path $registrypath -Force -PropertyType $registry_type -Value $value | Out-Null
    }
    else {
      New-ItemProperty -Name $name -Path $registrypath -Force -PropertyType $registry_type -Value $value | Out-Null | Out-Null
    }
  }

$registryPath = "HKCU:\Control Panel\Desktop"
$Name = "WallPaper"
$value = ""
$registry_type = "DWORD"
create_registry_key


#Small Desktop icons
$registryPath = "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop"
$Name = "IconSize"
$value = "36"
$registry_type = "DWORD"
create_registry_key

#Disable Windows spotlight features
$registryPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
$Name = "DisableWindowsSpotlightFeatures"
$value = "1"
$registry_type = "DWORD"
create_registry_key

#Deactivate sound setting communication 'Reduce the volume of other sounds by 80%'
$registryPath = "HKCU:\Software\Microsoft\Multimedia\Audio"
$Name = "UserDuckingPreference"
$value = "3"
$registry_type = "DWORD"
create_registry_key

#Explorer launch to "This PC"
$registryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$Name = "LaunchTo"
$value = "1"
$registry_type = "DWORD"
create_registry_key


#Disable Windows Web Search
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
$Name = "BingSearchEnabled"
$value = "0"
$registry_type = "DWORD"
create_registry_key


$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
$Name = "CortanaConsent"
$value = "0"
$registry_type = "DWORD"
create_registry_key

#Disable enhanced pointer precision
$registryPath = "HKCU:\Control Panel\Mouse"
$Name = "MouseSpeed"
$value = "0"
$registry_type = "DWORD"
create_registry_key


$registryPath = "HKCU:\Control Panel\Mouse"
$Name = "MouseThreshold1"
$value = "0"
$registry_type = "DWORD"
create_registry_key


$registryPath = "HKCU:\Control Panel\Mouse"
$Name = "MouseThreshold2"
$value = "0"
$registry_type = "DWORD"
create_registry_key


#Enable dark mode
$registryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
$Name = "AppsUseLightTheme"
$value = "0"
$registry_type = "DWORD"
create_registry_key


#Explorer tweaks
# Show all taskbar icons
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
$Name = "EnableAutoTray"
$value = "0"
$registry_type = "DWORD"
create_registry_key


#Choose "Show hidden files, folders, and drives"
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$Name = "Hidden"
$value = "1"
$registry_type = "DWORD"
create_registry_key


#Uncheck "Hide extensions for known file types"
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$Name = "HideFileExt"
$value = "0"
$registry_type = "DWORD"
create_registry_key


#Uncheck "Hide protected operating system files (Recommended)"
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$Name = "ShowSuperHidden"
$value = "0"
$registry_type = "DWORD"
create_registry_key


#ShowCortanaButton
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$Name = "ShowCortanaButton"
$value = "0"
$registry_type = "DWORD"
create_registry_key


#Disable task view button
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$Name = "ShowTaskViewButton"
$value = "0"
$registry_type = "DWORD"
create_registry_key


#Small taskbar icons
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$Name = "TaskbarSmallIcons"
$value = "1"
$registry_type = "DWORD"
create_registry_key


#disable background apps
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
$Name = "GlobalUserDisabled"
$value = "1"
$registry_type = "DWORD"
create_registry_key


#Enable Windows 10 context menu
$registryPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
$Name = "(Default)"
$value = ""
$registry_type = "String"
create_registry_key

#Show accent color on title bars and windows
$registryPath = "HKCU:\Software\Microsoft\Windows\DWM"
$Name = "ColorPrevalence"
$value = "0"
$registry_type = "String"
create_registry_key


#Disable ShowRecent file in Explorer
$registryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
$Name = "ShowRecent"
$value = "0"
$registry_type = "DWORD"
create_registry_key


#Disable ShowFrequent file in Explorer
$registryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
$Name = "ShowFrequent"
$value = "0"
$registry_type = "DWORD"
create_registry_key


#Enable Nvidia Sharpening
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS"
$Name = "EnableGR535"
$value = "0"
$registry_type = "DWORD"
create_registry_key


#Disable animations in Windows
$registryPath = "HKCU:\Control Panel\Desktop\WindowMetrics"
$Name = "MinAnimate"
$value = "1"
$registry_type = "String"
create_registry_key


#Disable transparancey
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
$Name = "EnableTransparency"
$value = "0"
$registry_type = "DWORD"
create_registry_key


#Disable sticky keys
$registryPath = "HKCU:\Control Panel\Accessibility\StickyKeys"
$Name = "Flags"
$value = "506"
$registry_type = "DWORD"
create_registry_key


#Taskbar Alignment left
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\"
$Name = "TaskbarAl"
$value = "0"
$registry_type = "DWORD"
create_registry_key


#Disable adverstising id
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
$Name = "Enabled"
$value = "0"
$registry_type = "DWORD"
create_registry_key


#Disable websites getting access to language list
$registryPath = "HKCU:\Control Panel\International\User Profile"
$Name = "HttpAcceptLanguageOptOut"
$value = "1"
$registry_type = "DWORD"
create_registry_key

#New-Item -ItemType File -Path 'C:\usercontext.txt'

# Restart PC to Apply All Changes
shutdown /r -t 1