<#
This script finds and removes the malware OneStart.ai, including the application itself, its processes, sub files, regristry keys, etc from the device.
It first will confirm or deny if there is the soecified malware on the device. Then asks if the user wants to remove it. 

Step 1: Detect OneStart.ai
Step 2: Ask user if they want removal (only if detected)
Step 3: Remove if user agrees
Step 4: Continue with original script
#>


$malName = "OneStart.ai"
$searchPatterns = @("OneStart.ai","OneStart*","OneStart.exe","OneStart.ps1")
$searchPaths = @(
    "$env:ProgramFiles",
    "$env:ProgramFiles(x86)",
    "$env:Windir",
    "$env:SystemRoot",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\AppData\Local",
    "$env:USERPROFILE\AppData\Roaming",
    "$env:USERPROFILE\Start Menu\Programs\Startup",
    "C:\Users"
)
$foundItems = @()
$foundProcesses = @()
$foundScheduledTasks = @()
$foundRegistry = @()

# Functions
function Search-Files {
    param($paths, $patterns)
    $results = @()
    foreach ($p in $paths) {
        foreach ($pat in $patterns) {
            try {
                $items = Get-ChildItem -Path $p -Filter $pat -Recurse -ErrorAction SilentlyContinue -Force
                if ($items) { $results += $items }
            } catch {}
        }
    }
    $results | Sort-Object -Property FullName -Unique
}

function Search-Processes {
    param($patterns)
    $procResults = @()
    foreach ($pat in $patterns) {
        try {
            $name = $pat -replace '\*',''
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $p = Get-Process -Name $name -ErrorAction SilentlyContinue
            if ($p) { $procResults += $p }
        } catch {}
    }
    $procResults | Select-Object -Unique
}

function Search-ScheduledTasks {
    param($patterns)
    $st = @()
    try {
        $all = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($task in $all) {
            foreach ($pat in $patterns) {
                if ($task.TaskName -like $pat -or $task.TaskPath -like $pat) {
                    $st += $task
                } elseif ($task.Actions.Execute -like $pat) {
                    $st += $task
                }
            }
        }
    } catch {}
    $st | Select-Object -Unique
}

function Search-Registry {
    param($patterns)
    $regMatches = @()
    $hives = @("HKLM:\SOFTWARE","HKLM:\SOFTWARE\Wow6432Node","HKCU:\SOFTWARE")
    foreach ($h in $hives) {
        foreach ($pat in $patterns) {
            try {
                $items = Get-ChildItem -Path $h -Recurse -ErrorAction SilentlyContinue |
                         Where-Object { $_.Name -like "*$pat*" -or $_.PSPath -like "*$pat*" }
                if ($items) { $regMatches += $items }
            } catch {}
        }
    }
    $regMatches | Select-Object -Unique
}

function Remove-Detected {
    param(
        [array]$files,
        [array]$processes,
        [array]$tasks,
        [array]$registryKeys
    )

    # Stop processes
    foreach ($p in $processes) {
        try { Stop-Process -Id $p.Id -Force -ErrorAction Stop; Write-Output "Stopped $($p.ProcessName)" }
        catch { Write-Output "Failed to stop $($p.ProcessName): $_" }
    }

    # Remove tasks
    foreach ($t in $tasks) {
        try { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false; Write-Output "Removed task $($t.TaskName)" }
        catch { Write-Output "Failed to remove $($t.TaskName): $_" }
    }

    # Remove files/folders
    foreach ($f in $files) {
        try {
            Remove-Item -LiteralPath $f.FullName -Recurse -Force -ErrorAction Stop
            Write-Output "Removed $($f.FullName)"
        } catch { Write-Output "Failed to remove $($f.FullName): $_" }
    }

    # Remove registry keys
    foreach ($r in $registryKeys) {
        try { Remove-Item -Path $r.PSPath -Recurse -Force -ErrorAction Stop; Write-Output "Removed $($r.PSPath)" }
        catch { Write-Output "Failed to remove $($r.PSPath): $_" }
    }
}

# Step 1: Detection 
Write-Output "Searching for $malName..."

$foundItems = Search-Files -paths $searchPaths -patterns $searchPatterns
$foundProcesses = Search-Processes -patterns $searchPatterns
$foundScheduledTasks = Search-ScheduledTasks -patterns $searchPatterns
$foundRegistry = Search-Registry -patterns $searchPatterns

$foundAny = $false
if ($foundItems -or $foundProcesses -or $foundScheduledTasks -or $foundRegistry) { $foundAny = $true }

# Step 2 & 3: Prompt and Removal 
if ($foundAny) {
    Write-Output "There is $malName found on this device"

    # Summarize findings
    if ($foundProcesses) { Write-Output "Processes:"; $foundProcesses | ForEach-Object { $_.ProcessName } }
    if ($foundItems) { Write-Output "Files:"; $foundItems | ForEach-Object { $_.FullName } }
    if ($foundScheduledTasks) { Write-Output "Tasks:"; $foundScheduledTasks | ForEach-Object { $_.TaskName } }
    if ($foundRegistry) { Write-Output "Registry:"; $foundRegistry | ForEach-Object { $_.PSPath } }

    $resp = Read-Host "Would you like to attempt removal of detected $malName items? (Y/N)"
    if ($resp -match '^(Y|y)') {
        Remove-Detected -files $foundItems -processes $foundProcesses -tasks $foundScheduledTasks -registryKeys $foundRegistry
    } else {
        Write-Output "User declined removal. No changes made."
    }
} else {
    Write-Output "There is no $malName found on this device"
}

# Step 4: Removal


<#
This script finds and removes the malware OneStart.ai, including the application itself, its processes, sub files, regristry keys, etc from the device.
It first will confirm or deny if there is the soecified malware on the device. Then asks if the user wants to remove it. 
=
USAGE: Run in an elevated PowerShell session for removal steps to succeed.
#>


$malName = "OneStart.ai"   # Friendly name shown in messages
$searchPatterns = @("OneStart.ai","OneStart*","OneStart.exe","OneStart.ps1")
$searchPaths = @(
    "$env:ProgramFiles",
    "$env:ProgramFiles(x86)",
    "$env:Windir",
    "$env:SystemRoot",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\AppData\Local",
    "$env:USERPROFILE\AppData\Roaming",
    "$env:USERPROFILE\Start Menu\Programs\Startup",
    "C:\Users"
)
$foundItems = @()
$foundProcesses = @()
$foundScheduledTasks = @()
$foundRegistry = @()

# Searches the files on a device.
function Search-Files {
    param($paths, $patterns)
    $results = @()
    foreach ($p in $paths) {
        foreach ($pat in $patterns) {
            try {
                # Use -Force to include hidden files; SilentlyContinue to skip access errors
                $items = Get-ChildItem -Path $p -Filter $pat -Recurse -ErrorAction SilentlyContinue -Force -Force:$false
                if ($items) { $results += $items }
            } catch {
                # ignore permission/path errors
            }
        }
    }
    # Deduplicate by FullName
    $results | Sort-Object -Property FullName -Unique
}

#Searches the processes on the device
function Search-Processes {
    param($patterns)
    $procResults = @()
    foreach ($pat in $patterns) {
        try {
            $name = $pat -replace '\*',''
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $p = Get-Process -Name $name -ErrorAction SilentlyContinue
            if ($p) { $procResults += $p }
        } catch { }
    }
    $procResults | Select-Object -Unique
}

#Searches the scheduled tasksd
function Search-ScheduledTasks {
    param($patterns)
    $st = @()
    try {
        $all = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($task in $all) {
            foreach ($pat in $patterns) {
                if ($task.TaskName -like $pat -or $task.TaskPath -like $pat) {
                    $st += $task
                } else {
                    # check registration info/author/path for pattern match
                    $td = ($task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue) 
                    if ($td -and ($td.Author -like $pat -or $task.Actions.Execute -like $pat)) {
                        $st += $task
                    }
                }
            }
        }
    } catch { }
    $st | Select-Object -Unique
}

#Searches the Regristy
function Search-Registry {
    param($patterns)
    $regMatches = @()
    $hives = @("HKLM:\SOFTWARE","HKLM:\SOFTWARE\Wow6432Node","HKCU:\SOFTWARE")
    foreach ($h in $hives) {
        foreach ($pat in $patterns) {
            try {
                $items = Get-ChildItem -Path $h -Recurse -ErrorAction SilentlyContinue |
                         Where-Object { $_.Name -like "*$pat*" -or $_.PSPath -like "*$pat*" }
                if ($items) { $regMatches += $items }
            } catch {}
        }
    }
    $regMatches | Select-Object -Unique
}

function Confirm-And-Remove {
    param(
        [array]$files,
        [array]$processes,
        [array]$tasks,
        [array]$registryKeys
    )

    Write-Host ""
    $resp = Read-Host "Would you like to attempt removal of detected OneStart.ai items? (Y/N)"
    if ($resp -notin @("Y","y","Yes","yes")) {
        Write-Output "Removal canceled by user. No changes made."
        return
    }

    # Attempt to stop processes
    if ($processes -and $processes.Count -gt 0) {
        Write-Output "Stopping detected processes..."
        foreach ($p in $processes) {
            try {
                Stop-Process -Id $p.Id -Force -ErrorAction Stop
                Write-Output "Stopped process $($p.ProcessName) (PID $($p.Id))"
            } catch {
                Write-Output "Failed to stop process $($p.ProcessName) (PID $($p.Id)): $_"
            }
        }
    }

    # Attempt to unregister scheduled tasks
    if ($tasks -and $tasks.Count -gt 0) {
        Write-Output "Removing scheduled tasks..."
        foreach ($t in $tasks) {
            try {
                Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop
                Write-Output "Removed scheduled task $($t.TaskName)"
            } catch {
                Write-Output "Failed to remove task $($t.TaskName): $_"
            }
        }
    }

    # Remove files
    if ($files -and $files.Count -gt 0) {
        Write-Output "Removing files and folders..."
        foreach ($f in $files) {
            try {
                if ($f.PSIsContainer) {
                    Remove-Item -LiteralPath $f.FullName -Recurse -Force -ErrorAction Stop
                    Write-Output "Removed folder: $($f.FullName)"
                } else {
                    Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                    Write-Output "Removed file: $($f.FullName)"
                }
            } catch {
                Write-Output "Failed to remove $($f.FullName): $_"
            }
        }
    }

    # Remove registry keys (attempt)
    if ($registryKeys -and $registryKeys.Count -gt 0) {
        Write-Output "Attempting to remove registry keys/values..."
        foreach ($r in $registryKeys) {
            try {
                # If it's a key path, attempt Remove-Item
                $path = $r.PSPath
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Output "Removed registry item: $path"
            } catch {
                Write-Output "Failed to remove registry item $($r.Name): $_"
            }
        }
    }

    Write-Output "Removal attempts complete. It is recommended to reboot and scan with an up-to-date AV/EDR tool."
}

# Detection 
Write-Output "Searching for $malName on this device... (this may take a few moments)"

# File search
$foundItems = Search-Files -paths $searchPaths -patterns $searchPatterns

# Process search
$foundProcesses = Search-Processes -patterns $searchPatterns

# Scheduled tasks
$foundScheduledTasks = Search-ScheduledTasks -patterns $searchPatterns

# Registry
$foundRegistry = Search-Registry -patterns $searchPatterns

$foundAny = $false
if (($foundItems -and $foundItems.Count -gt 0) -or ($foundProcesses -and $foundProcesses.Count -gt 0) -or ($foundScheduledTasks -and $foundScheduledTasks.Count -gt 0) -or ($foundRegistry -and $foundRegistry.Count -gt 0)) {
    $foundAny = $true
}

if ($foundAny) {
    Write-Output "There is $malName found on this device"
    # show summary
    if ($foundProcesses -and $foundProcesses.Count -gt 0) {
        Write-Output "Detected processes:"
        $foundProcesses | ForEach-Object { Write-Output ("  {0} (PID {1})" -f $_.ProcessName, $_.Id) }
    }
    if ($foundItems -and $foundItems.Count -gt 0) {
        Write-Output "Detected files/folders (first 20 shown):"
        $foundItems | Select-Object -First 20 | ForEach-Object { Write-Output ("  {0}" -f $_.FullName) }
    }
    if ($foundScheduledTasks -and $foundScheduledTasks.Count -gt 0) {
        Write-Output "Detected scheduled tasks:"
        $foundScheduledTasks | ForEach-Object { Write-Output ("  {0}{1}" -f $_.TaskPath, $_.TaskName) }
    }
    if ($foundRegistry -and $foundRegistry.Count -gt 0) {
        Write-Output "Detected registry items (first 20 shown):"
        $foundRegistry | Select-Object -First 20 | ForEach-Object { Write-Output ("  {0}" -f $_.PSPath) }
    }

    # Confirm removal
    Confirm-And-Remove -files $foundItems -processes $foundProcesses -tasks $foundScheduledTasks -registryKeys $foundRegistry
} else {
    Write-Output "There is no $malName found on this device"
}



$process = Get-Process OneStart -ErrorAction SilentlyContinue
if ($process) {
    $process | Stop-Process -Force -ErrorAction SilentlyContinue
}
$process = Get-Process UpdaterSetup -ErrorAction SilentlyContinue
if ($process) {
    $process | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

$user_list = Get-Item C:\users\* | Select-Object Name -ExpandProperty Name
foreach ($user in $user_list) {
    $installers = @(Get-ChildItem "C:\users\$user\Downloads" -Recurse -Filter "OneStart*.exe" | ForEach-Object { $_.FullName })
    foreach ($install in $installers) {
        if (Test-Path -Path $install) {
            Remove-Item $install -ErrorAction SilentlyContinue
            if (Test-Path -Path $install) {
                Write-Host "Failed to remove OneStart installer -> $install"
            }
        }
    }

    $installers = @(Get-ChildItem "C:\users\$user\Downloads" -Recurse -Filter "*OneStart*.msi" | ForEach-Object { $_.FullName })
    foreach ($install in $installers) {
        if (Test-Path -Path $install) {
            Remove-Item $install -ErrorAction SilentlyContinue
            if (Test-Path -Path $install) {
                Write-Host "Failed to remove OneStart installer -> $install"
            }
        }
    }

    $paths = @(
        "C:\Users\$user\AppData\Local\OneStart.ai",
        "C:\Users\$user\OneStart.ai",
        "C:\Users\$user\Desktop\OneStart.lnk",
        "C:\Users\$user\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\OneStart.lnk",
        "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneStart.lnk",
        "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\PDF Editor.lnk",
        "C:\Users\$user\AppData\Roaming\NodeJs",
        "C:\Users\$user\AppData\Roaming\PDF Editor"
    )
    foreach ($path in $paths) {
        if (Test-Path -Path $path) {
            Remove-Item $path -Force -Recurse -ErrorAction SilentlyContinue
            if (Test-Path -Path $path) {
                Write-Host "Failed to remove OneStart -> $path"
            }
        }
    }
}

$paths = @(
    "C:\WINDOWS\system32\config\systemprofile\AppData\Local\OneStart.ai",
    "C:\WINDOWS\system32\config\systemprofile\PDFEditor"
)
foreach ($path in $paths) {
    if (test-path -Path $path) {
        Remove-Item $path -Force -Recurse -ErrorAction SilentlyContinue
            if (Test-Path -Path $path) {
                Write-Host "Failed to remove OneStart -> $path"
            }
    }
}    

$tasks = @(
    "C:\Windows\System32\Tasks\OneStartUser",
    "C:\windows\system32\tasks\OneStartAutoLaunchTask*",
    "C:\Windows\System32\Tasks\PDFEditorScheduledTask",
    "C:\Windows\System32\Tasks\PDFEditorUScheduledTask",
    "C:\Windows\System32\Tasks\sys_component_health_*"

)
foreach ($task in $tasks) {
    if (Test-Path -Path $task) {
        Remove-Item $task -Force -Recurse -ErrorAction SilentlyContinue
        if (Test-Path -Path $task) {
            Write-Host "Failed to remove OneStart task -> $task"
        }
    }
}

$taskCacheKeys = @(
    "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\OneStartAutoLaunchTask*",
    "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\OneStartUser",
    "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\PDFEditorScheduledTask",
    "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\PDFEditorUScheduledTask",
    "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\sys_component_health_*",
    "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{88E532D6-7FD4-4229-B0E8-5E196DBF78B2}"
)
foreach ($taskCacheKey in $taskCacheKeys) {
    if (Test-Path -Path $taskCacheKey) {
        Remove-Item $taskCacheKey -Recurse -ErrorAction SilentlyContinue
        if (Test-Path -Path $taskCacheKey) {
            Write-Host "Failed to remove OneStart -> $taskCacheKey"
        }
    }
}

$registryKeys = @(
    'Registry::HKLM\Software\WOW6432Node\Microsoft\Tracing\OneStart_RASAPI32',
    'Registry::HKLM\Software\WOW6432Node\Microsoft\Tracing\OneStart_RASMANCS',
    'Registry::HKLM\Software\Microsoft\MediaPlayer\ShimInclusionList\onestart.exe'
)
foreach ($key in $registryKeys) {
    if (Test-Path -Path $key) {
        Remove-Item $key -Recurse -ErrorAction SilentlyContinue
        if (Test-Path -Path $key) {
            Write-Host "Failed to remove OneStart -> $key"
        }
    }
}

$sid_list = Get-Item -Path "Registry::HKU\S-*" | Select-String -Pattern "S-\d-(?:\d+-){5,14}\d+" | ForEach-Object { $_.ToString().Trim() }
foreach ($sid in $sid_list) {
    if ($sid -notlike "*_Classes*") {
        $registryPaths = @(
            "Registry::$sid\Software\Clients\StartMenuInternet\OneStart.IOZDYLUF4W5Y3MM3N77XMXEX6A",
            "Registry::$sid\Software\OneStart.ai",
            "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneStart.ai OneStart",
            "Registry::$sid\Software\PDFEditor",
            "Registry::$sid\Software\Clients\StartMenuInternet\OneStart.25VKDQVMIQGWARCLC23VYGDER4",
            "Registry::$sid\Software\Classes\CLSID\{4DAC24AB-B340-4B7E-AD01-1504A7F59EEA}\LocalServer32",
            "Registry::$sid\Software\Classes\CLSID\{75828ED1-7BE8-45D0-8950-AA85CBF74510}\LocalServer32",
            "Registry::$sid\Software\Classes\CLSID\{A2C6CB58-C076-425C-ACB7-6D19D64428CD}\LocalServer32",
            "Registry::$sid\Software\Classes\CLSID\{A45DDD96-C17C-50A3-BD69-8D064F864B24}\LocalServer32",
            "Registry::$sid\Software\Classes\CLSID\{B5B6376D-5E59-5CB2-A34D-617C21A3A240}\LocalServer32",
            "Registry::$sid\Software\Classes\OneStart.aiUpdate.Update3WebUser",
            "Registry::$sid\Software\Software\Classes\OSBHTML.25VKDQVMIQGWARCLC23VYGDER4"
        )
        foreach ($regPath in $registryPaths) {
            if (Test-Path -Path $regPath) {
                Remove-Item $regPath -Recurse -ErrorAction SilentlyContinue
                if (Test-Path -Path $regPath) {
                    Write-Host "Failed to remove OneStart -> $regPath"
                }
            }
        }
        $runKeys = @("OneStartUpdate", "OneStartBarUpdate","OneStartBar","OneStart", "OneStartChromium","OneStartUpdaterTaskUser*","PDFEditor*")
        foreach ($runKey in $runKeys) {
            $keypath = "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Run"
            if ((Get-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue)) {
                Remove-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue
                if ((Get-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue)) {
                    Write-Host "Failed to remove OneStart -> $keypath.$runKey"
                }
            }
        }
        $runKeys = @("OneStart*")
        foreach ($runKey in $runKeys) {
            $keypath = "Registry::$sid\Software\RegisteredApplications"
            if ((Get-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue)) {
                Remove-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue
                if ((Get-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue)) {
                    Write-Host "Failed to remove OneStart -> $keypath.$runKey"
                }
            }
        }
    }
}

