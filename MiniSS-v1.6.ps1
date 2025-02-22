$ErrorActionPreference = "SilentlyContinue"
clear-host
function MainMenu {
cls
Logo                                                          
Write-Host @"
        [1] Prefetch Tool's            [6] LastActivityView
        [2] Pcasvc-Execution           [7] SystemInformer
        [3] Everything                 [8] BAM Tool's
        [4] Convertor's Tool           [9] Signatures Tool's
        [5] ExecutedProgramsList       [0] MACETA

"@
Write-Host -ForegroundColor Yellow "        [Next] Next Page"
Write-Host -ForegroundColor Yellow "        [Exit] Exit and close Script Tool"
}
function Menu2 {
cls
Logo
Write-Host @"
        [1] USBDeview                  [6] EDDv310
        [2] Luyten                     [7] AppCompatCacheParser
        [3] Scheduler parser           [8] Velociraptor
        [4] JournalTrace               [9] Uniode
        [5] InjGen                     [0] Service-Check

"@
Write-Host -ForegroundColor Yellow "        [Back] Back for Main Page"
Write-Host -ForegroundColor Yellow "        [Exit] Exit and close Script Tool"
}

function Logo {
Write-Host @"

                            ███╗   ███╗██╗███╗   ██╗██╗    ███████╗███████╗
                            ████╗ ████║██║████╗  ██║██║    ██╔════╝██╔════╝
                            ██╔████╔██║██║██╔██╗ ██║██║    ███████╗███████╗
                            ██║╚██╔╝██║██║██║╚██╗██║██║    ╚════██║╚════██║
                            ██║ ╚═╝ ██║██║██║ ╚████║██║    ███████║███████║
                            ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝    ╚══════╝╚══════╝
                                               
                            ████████╗ ██████╗  ██████╗ ██╗                 
                            ╚══██╔══╝██╔═══██╗██╔═══██╗██║                 
                               ██║   ██║   ██║██║   ██║██║                 
                               ██║   ██║   ██║██║   ██║██║                 
                               ██║   ╚██████╔╝╚██████╔╝███████╗            
                               ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝  
       ════════════════════════════════════════════════════════════════════════════════════════════════════
"@ -ForegroundColor Red                                                           
    Write-Host -ForegroundColor Blue "       By Smooth | Discord: smoothzada"
    Write-Host ""
}
function Test-Admin {;$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent());$currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);}
if (!(Test-Admin)) {
    Write-Warning "Execute o script como Administrador"
    Start-Sleep 5
    Exit
}
function PathVerify {
    param (
        [string]$FolderPath
    )
    
    if (Test-Path $FolderPath -PathType Container) {
        return $true
    } else {
        Write-Host "Pasta não encontrada" -ForegroundColor Red
        Start-Sleep -Seconds 1
        cls
        return $false
    }
}
    do {
        Logo
        $OutfilePath = Read-Host "Digite o caminho completo da pasta"
        $foundPath = PathVerify -FolderPath $OutfilePath
    } while (-not $foundPath)

cls
MainMenu

while ($true) {
    cd $OutfilePath
    $Choser = Read-Host "Escolha"

    if ($Choser -eq 1) {
        cls
        Logo 
        Write-Host "Escolha uma Opção para Prefetch:"
        Write-Host ""
        Write-Host "        [1] Donwload WinPrefetchView"
        Write-Host "        [2] Download PrefetchParser - By Spokwn"
        Write-Host "        [3] Prefetch Scan - By Smooth"
        Write-Host "        [4] Cancelar"
        Write-Host ""
        $ChoserPF = Read-Host "Digite o número da opção"

        if ($ChoserPF -eq 1) {
            Write-Host "Baixando WinPrefetchView..."
            $url = "https://www.nirsoft.net/utils/winprefetchview-x64.zip"
            $destinationFile = "$OutfilePath\winprefetchview-x64.zip"
            Invoke-WebRequest -Uri $url -OutFile $destinationFile
            Write-Host "Download completo!" -ForegroundColor Green
            Start-Sleep -Seconds 1  
            cls
        }
        elseif ($ChoserPF -eq 2) {
            Write-Host "Baixando Spokwn PrefetchParser..."
            $urlPB = "https://github.com/spokwn/prefetch-parser/releases/download/v1.5.4/PrefetchParser.exe"
            $destinationFilePB = "$OutfilePath\PrefetchParser.exe"
            Invoke-WebRequest -Uri $urlPB -OutFile $destinationFilePB
            Write-Host "Download completo!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            cls
        }
        elseif ($ChoserPF -eq 3) {
    cls
    logo
    Write-Host "Executando Prefetch Scan..."

    $readOnlyFiles = @()
    $hiddenFiles = @()
    $dosModeFiles = @()
    $suspiciousFiles = @()

    Write-Host "Scanning..."
    $prefetchFiles = Get-ChildItem -Path C:\Windows\Prefetch -File -Force | 
        Sort-Object LastWriteTime -Descending

    # Etapa 1
    $readOnlyFiles = $prefetchFiles | Where-Object { $_.Attributes -match "ReadOnly" }
    $hiddenFiles = $prefetchFiles | Where-Object { $_.Attributes -match "Hidden" }

    # Etapa 2
    $dosModeFiles = $prefetchFiles | 
        Where-Object { (Get-Content $_.FullName -ErrorAction SilentlyContinue) -match "This program cannot be run in DOS mode" }

    # Etapa 3
    $suspiciousKeywords = @("Monaco", "Clicker", "Load", "slinky", "epic", "IceTea", "koid", "exelon", "LithiumLite", "Vape", "zoomin", "dope", "Eternal", "axenta", "medusa", "BReeze", "Raid0", "Raido", "Dream", "Whiteout", "Cleaner")
    $suspiciousFiles = $prefetchFiles | 
        Where-Object {
            $fileName = $_.Name.ToLower()
            $suspiciousKeywords | ForEach-Object { 
                if ($fileName -like "*$_*".ToLower()) { 
                    return $true 
                }
            }
        }

    Write-Host ""
    Write-Host "====================RESULTS===================="
    Write-Host ""


    if ($readOnlyFiles.Count -gt 0 -or $hiddenFiles.Count -gt 0) {
        Write-Host "Found Read-only or hidden files:" -ForegroundColor Green
        if ($readOnlyFiles.Count -gt 0) {
            Write-Host ""
            $readOnlyFiles | ForEach-Object { Write-Host "        ReadOnly File: $($_.Name) | Attributes: $($_.Attributes) | LastWriteTime: $($_.LastWriteTime)" -ForegroundColor Yellow }
        }
        if ($hiddenFiles.Count -gt 0) {
            $hiddenFiles | ForEach-Object { Write-Host "        Hidden File: $($_.Name) | Attributes: $($_.Attributes) | LastWriteTime: $($_.LastWriteTime)" -ForegroundColor Yellow }
        }
    } else {
        Write-Host "No read-only or hidden files found" -ForegroundColor Red
    }

    if ($dosModeFiles.Count -gt 0) {
        Write-Host ""
        Write-Host "Found Modified extensions in Prefetch:" -ForegroundColor Green
        Write-Host ""
        $dosModeFiles | ForEach-Object { Write-Host "        File: $($_.Name) | LastWriteTime: $($_.LastWriteTime)" -ForegroundColor Yellow }
    } else {
        Write-Host "No modified extensions found in Prefetch" -ForegroundColor Red
    }

    if ($suspiciousFiles.Count -gt 0) {
        Write-Host ""
        Write-Host "Found Suspicious prefetch files:" -ForegroundColor Green
        Write-Host ""
        $suspiciousFiles | ForEach-Object { Write-Host "        File: $($_.Name) | LastWriteTime: $($_.LastWriteTime)" -ForegroundColor Yellow }
    } else {
        Write-Host "No suspicious prefetch files found" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "Pressione Enter para continuar..." -ForegroundColor Cyan
    Read-Host
    cls
    Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/bacanoicua/Screenshare/main/RedLotusPrefetchIntegrityAnalyzer.ps1)
    pause
    cls
}


    }
    elseif ($Choser -eq 2) {
        cls
        Logo 
        Write-Host "Escolha uma Opção para Service-Execution:"
        Write-Host ""
        Write-Host "        [1] Zack-src Service execution"
        Write-Host "        [2] Spokwn Service execution"
        Write-Host "        [3] Cancelar"
        Write-Host ""
        $Choser2 = Read-Host "Digite o número da opção"

        if ($Choser2 -eq 1) {
            Write-Host "Baixando Zack-src Service execution..."
            $url2 = "https://github.com/Zack-src/Service-Execution/releases/download/1.0/Service-Execution.exe"
            $destinationFile2 = "$OutfilePath\Service-Execution.exe"
            Invoke-WebRequest -Uri $url2 -OutFile $destinationFile2
            Write-Host "Download completo!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            cls
        }
        elseif ($Choser2 -eq 2) {
            Write-Host "Baixando Spokwn Service execution..."
            $url3 = "https://github.com/spokwn/pcasvc-executed/releases/download/v0.8.6/PcaSvcExecuted.exe"
            $destinationFile3 = "$OutfilePath\PcaSvcExecuted.exe"
            Invoke-WebRequest -Uri $url3 -OutFile $destinationFile3
            Write-Host "Download completo!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            cls
        }
        elseif ($Choser2 -eq 3) {
            Write-Host "Operação cancelada."
            Start-Sleep -Seconds 1
            cls
        }
        else {
            Write-Host "Opção inválida. Tente novamente."
            Start-Sleep -Seconds 1  
            cls  
        }
    }
    elseif ($Choser -eq 3) {
        Write-Host "Baixando Everything..."
        $url4 = "https://www.voidtools.com/Everything-1.4.1.1026.x86-Setup.exe"
        $destinationFile4 = "$OutfilePath\Everything-1.4.1.1026.x86-Setup.exe"
        Invoke-WebRequest -Uri $url4 -OutFile $destinationFile4
        Write-Host "Download completo!" -ForegroundColor Green
        Start-Sleep -Seconds 1
        Write-Host "Setup Everything..."
        Start-Sleep -Seconds 1
        Start-Process -FilePath $destinationFile4
        cls
    }
        elseif ($Choser -eq 4) {
        cls
        Logo 
        Write-Host "Escolha uma Opção para Convertor"
        Write-Host ""
        Write-Host "        [1] DPS HardDiskConvertor"
        Write-Host "        [2] Bfe query user convertor"
        Write-Host "        [3] Cancelar"
        Write-Host ""
        $Choser3 = Read-Host "Escolha"

        if ($Choser3 -eq 1) {
            Write-Host "Executando RedLotus Dps HardDiskConvertor"
            Start-Sleep -Seconds 1
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
            nvoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/bacanoicua/Screenshare/main/RedLotusHardDiskVolumeConverter.ps1)
            Write-Host "Script executado com sucesso!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            cls
        }
        elseif ($Choser3 -eq 2) {
            Write-Host "Executando RedLotus Dps HardDiskConvertor"
            Start-Sleep -Seconds 1
            $BFEFile = Read-Host "Insira o caminho do arquivo de entrada"
            if (!(Test-Path $BFEFile)) {
                Write-Host "Erro: O arquivo especificado não foi encontrado. Verifique o caminho e tente novamente." -ForegroundColor Red
                exit
            }
            $outputDir = Read-Host "Insira o caminho da pasta onde deseja salvar o arquivo convertido"
            if (!(Test-Path $outputDir)) {
                New-Item -ItemType Directory -Path $outputDir | Out-Null
            }
            $outputFile = Join-Path -Path $outputDir -ChildPath "NewPaths.txt"
            $regex = "([A-Za-z]:\\[^}]+)"
            try {
                $conteudo = Get-Content -Path $BFEFile
                $NewPaths = @()

                foreach ($linha in $conteudo) {
                    if ($linha -match $regex) {
                        $NewPaths += $matches[1]
                    }
                }
                $NewPaths | Out-File -FilePath $outputFile -Encoding UTF8
                Write-Host "Conversão concluída! Arquivo salvo em: $outputFile" -ForegroundColor Green
                pause
            } catch {
                Write-Host "Erro ao converter o arquivo: $_" -ForegroundColor Red
            }

        }
        elseif ($Choser3 -eq 3) {
            Write-Host "Operação cancelada."
            Start-Sleep -Seconds 1
            cls
        }
        else {
            Write-Host "Opção inválida. Tente novamente."
            Start-Sleep -Seconds 1  
            cls  
        }
    }
        elseif ($Choser -eq 5) {
        Write-Host "Baixando ExecutedProgramsList..."
        $url6 = "https://www.nirsoft.net/utils/executedprogramslist.zip"
        $destinationFile6 = "$OutfilePath\executedprogramslist.zip"
        Invoke-WebRequest -Uri $url6 -OutFile $destinationFile6
        Write-Host "Download completo!" -ForegroundColor Green
        Start-Sleep -Seconds 1  
        cls
    }
    elseif ($Choser -eq 6) {
        Write-Host "Baixando LastActivityView..."
        $url7 = "https://www.nirsoft.net/utils/lastactivityview.zip"
        $destinationFile7 = "$OutfilePath\lastactivityview.zip"
        Invoke-WebRequest -Uri $url7 -OutFile $destinationFile7
        Write-Host "Download completo!" -ForegroundColor Green
        Start-Sleep -Seconds 1  
        cls
    }
    elseif ($Choser -eq 7) {
        Write-Host "Baixando SystemInformer..."
        $url8 = "https://github.com/winsiderss/si-builds/releases/download/3.2.25004/systeminformer-3.2.25004-canary-setup.exe"
        $destinationFile8 = "$OutfilePath\systeminformer-3.2.25004-canary-setup.exe"
        Invoke-WebRequest -Uri $url8 -OutFile $destinationFile8
        Write-Host "Download completo!" -ForegroundColor Green
        Start-Sleep -Seconds 1
        Write-Host "Setup SystemInformer..."
        Start-Sleep -Seconds 1
        Start-Process -FilePath $destinationFile8  
        cls
    }
    elseif ($Choser -eq 8) {
        cls
        Logo 
        Write-Host "Escolha uma Opção para BAM"
        Write-Host ""
        Write-Host "        [1] RedLotus BAM"
        Write-Host "        [2] BAMParser - Spokwn"
        Write-Host "        [3] Cancelar"
        Write-Host ""
        $Choser3 = Read-Host "Escolha"

        if ($Choser3 -eq 1) {
            Write-Host "Executando RedLotus BAM tool"
            Start-Sleep -Seconds 1
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
            Invoke-Expression (Invoke-RestMethod "https://raw.githubusercontent.com/PureIntent/ScreenShare/main/RedLotusBam.ps1")
            Write-Host "Script executado com sucesso!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            cls
        }
        elseif ($Choser3 -eq 2) {
            Write-Host "Baixando Spokwn BAMParser..."
            $url9 = "https://github.com/spokwn/BAM-parser/releases/download/v1.2.7/BAMParser.exe"
            $destinationFile9 = "$OutfilePath\BamParser.exe"
            Invoke-WebRequest -Uri $url9 -OutFile $destinationFile9
            Write-Host "Download completo!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            cls
        }
        elseif ($Choser3 -eq 3) {
            Write-Host "Operação cancelada."
            Start-Sleep -Seconds 1
            cls
        }
        else {
            Write-Host "Opção inválida. Tente novamente."
            Start-Sleep -Seconds 1  
            cls  
        }
    }
    elseif ($Choser -eq 9){
        cls
                Logo 
                Write-Host "Escolha uma Opção para Signatures"
                Write-Host ""
                Write-Host "        [1] RedLotusSignatures"
                Write-Host "        [2] PathParser - Spokwn"
                Write-Host "        [3] Cancelar"
                Write-Host ""
                $Choser5 = Read-Host "Digite o número da opção"

                if ($Choser5 -eq 1) {
                    Write-Host "Executando RedLotusSignatures tool"
                    Start-Sleep -Seconds 1
                    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
                    Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/bacanoicua/Screenshare/main/RedLotusSignatures.ps1)
                    Write-Host "Script executado com sucesso!" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    cls
                }
                elseif ($Choser5 -eq 2) {
                    Write-Host "Baixando Spokwn PathParser..."
                    $url10 = "https://github.com/spokwn/PathsParser/releases/download/v1.0.9/PathsParser.exe"
                    $destinationFile10 = "$OutfilePath\PathsParser.exe"
                    Invoke-WebRequest -Uri $url10 -OutFile $destinationFile10
                    Write-Host "Download completo!" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    cls
                }
                elseif ($Choser5 -eq 3) {
                    Write-Host "Operação cancelada."
                    Start-Sleep -Seconds 1
                    cls
                }
                else {
                    Write-Host "Opção inválida. Tente novamente."
                    Start-Sleep -Seconds 1  
                    cls  F
                }
    }
    elseif ($Choser -eq 0){
    Write-Host "Baixando MACETA Tool"  
                $url11 = "https://github.com/RRancio/Exec/raw/main/Files/newmaceta.exe"
                $destinationFile11 = "$OutfilePath\NewMaceta.exe"
                Invoke-WebRequest -Uri $url11 -OutFile $destinationFile11
                Write-Host "Download completo!" -ForegroundColor Green
                Start-Sleep -Seconds 1
                cls
    }






    #menu2
    elseif ($Choser -match "^next$") {
    cls
    do {
        Menu2
        $Choser4 = Read-Host "Escolha uma opção"

        if ($Choser4 -eq 1) {
                $url12 = "https://www.nirsoft.net/utils/usbdeview.zip"
                $destinationFile12 = "$OutfilePath\USBDeview.zip"
                Invoke-WebRequest -Uri $url12 -OutFile $destinationFile12
                Write-Host "Download completo!" -ForegroundColor Green
                Start-Sleep -Seconds 1
                cls
            }
            elseif ($Choser4 -eq 2) {
            cls
            Logo 
            Write-Host "Escolha uma Opção para Luythen:"
            Write-Host ""
            Write-Host "        [1] luyten.jar"
            Write-Host "        [2] luyten.exe"
            Write-Host "        [3] Cancelar"
            Write-Host ""
        $ChoserLU = Read-Host "Digite o número da opção"

        if ($ChoserLU -eq 1) {
            Write-Host "Baixando Luyten"
            $urlLU = "https://github.com/deathmarine/Luyten/releases/download/v0.5.4_Rebuilt_with_Latest_depenencies/luyten-0.5.4.jar"
            $destinationFileLU = "$OutfilePath\luyten-0.5.4.jar"
            Invoke-WebRequest -Uri $urlLU -OutFile $destinationFileLU
            Write-Host "Download completo!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            cls
        }
        elseif ($ChoserLU -eq 2) {
            Write-Host "Baixando Luyten"
            $urlLU = "https://github.com/deathmarine/Luyten/releases/download/v0.5.4_Rebuilt_with_Latest_depenencies/luyten-0.5.4.exe"
            $destinationFileLU = "$OutfilePath\luyten-0.5.4.exe"
            Invoke-WebRequest -Uri $urlLU -OutFile $destinationFileLU
            Write-Host "Download completo!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            cls
        }
        elseif ($ChoserLU -eq 3) {
            Write-Host "Operação cancelada."
            Start-Sleep -Seconds 1
            cls
        }
        else {
            Write-Host "Opção inválida. Tente novamente."
            Start-Sleep -Seconds 1  
            cls  
        }
            }
            elseif ($Choser4 -eq 3) {
                cls
                Logo 
                Write-Host "Escolha uma Opção para Scheduler"
                Write-Host ""
                Write-Host "        [1] Exe Scheduler"
                Write-Host "        [2] SchedulerParser"
                Write-Host "        [3] User Task"
                Write-Host "        [4] Suspicious Scheduler"
                Write-Host "        [5] Service Checker"
                Write-Host "        [6] Cancelar"
                Write-Host ""
                $Choser6 = Read-Host "Digite o número da opção"

                if ($Choser6 -eq 1) {
                    Write-Host "Executando Script"
                    Start-Sleep -Seconds 1
                    Get-ChildItem -Path C:\Windows\System32\Tasks\ -Recurse | ForEach-Object {
                        Select-String -Path $_.FullName -Pattern ":\\" 
                    } | Out-Gridview
                    Write-Host "Script executado com sucesso!" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    cls
                    }
                    elseif ($Choser6 -eq 2) {
                    Write-Host "Executando Script"
                    Start-Sleep -Seconds 1
                    powershell -Command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/ObsessiveBf/Task-Scheduler-Parser/main/script.ps1')"
                    Start-Sleep -Seconds 2
                    Write-Host "Script executado com sucesso!" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    cls
                    }
                    elseif ($Choser6 -eq 3) {
                    Write-Host "Executando Script"
                    Start-Sleep -Seconds 1
                    $UserRN = $env:USERNAME
                    Start-Sleep -Seconds 1
                    Write-Host "Executando Script para o usuário: $UserRN"
                    Start-Sleep -Seconds 1
                    Get-ScheduledTask | Where-Object { $_.Author -match $UserRN } | Out-GridView
                    Write-Host "Script executado com sucesso!" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    cls
                    }
                    elseif ($Choser6 -eq 4) {
                    Write-Host "Executando Script"
                    Start-Sleep -Seconds 1
                        Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/nolww/project-mohr/refs/heads/main/SuspiciousScheduler.ps1')
                    Start-Sleep -Seconds 2
                    Write-Host "Script executado com sucesso!" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    cls
                    }
                    elseif ($Choser6 -eq 5) {
                    Write-Host "Executando Script"
                    Start-Sleep -Seconds 1
                        Add-Type -AssemblyName System.Windows.Forms

$servicos = Get-WmiObject Win32_Service | Select-Object `
    DisplayName, Name, StartMode, State, StartName, PathName

$servicosWindowsComuns = @(
    "C:\Windows\System32\svchost.exe",
    "C:\Windows\System32\lsass.exe",
    "C:\Windows\System32\wininit.exe",
    "C:\Windows\System32\winlogon.exe",
    "C:\Windows\System32\services.exe",
    "C:\WINDOWS\system32\wbem\WmiApSrv.exe",
    "C:\WINDOWS\system32\locator.exe",
    "C:\WINDOWS\System32\DriverStore\FileRepository\u0376118.inf_amd64_d3964dd16c191eeb\B371320\atiesrxx.exe",
    "C:\WINDOWS\system32\dllhost.exe",
    "C:\WINDOWS\system32\msdtc.exe",
    "C:\WINDOWS\system32\vssvc.exe",
    "C:\WINDOWS\system32\CredentialEnrollmentManager.exe",
    "C:\WINDOWS\system32\vds.exe",
    "C:\WINDOWS\system32\fxssvc.exe",
    "C:\WINDOWS\system32\GameInputSvc.exe",
    "C:\WINDOWS\system32\TieringEngineService.exe",
    "C:\WINDOWS\SysWow64\perfhost.exe",
    "C:\WINDOWS\servicing\TrustedInstaller.exe",
    "C:\WINDOWS\system32\snmptrap.exe",
    "C:\WINDOWS\system32\AppVClient.exe",
    "C:\WINDOWS\System32\DriverStore\FileRepository\nv_disp.inf_amd64_1e8724cced6e93d4\Display.NvContainer\...",
    "C:\WINDOWS\System32\OpenSSH\ssh-agent.exe",
    "C:\WINDOWS\system32\sppsvc.exe",
    "C:\WINDOWS\system32\DiagSvcs\DiagnosticsHub.StandardCollector.Service.exe",
    "C:\WINDOWS\Microsoft.NET\Framework64\v4.0.30319\SMsvcHost.exe",
    "C:\WINDOWS\system32\SensorDataService.exe",
    "C:\WINDOWS\system32\wbengine.exe",
    "C:\WINDOWS\system32\spectrum.exe",
    "C:\WINDOWS\system32\SecurityHealthService.exe",
    "C:\WINDOWS\system32\PerceptionSimulation\PerceptionSimulationService.exe",
    "C:\WINDOWS\system32\AgentService.exe",
    "C:\WINDOWS\system32\alg.exe",
    "C:\WINDOWS\system32\spoolsv.exe",
    "C:\WINDOWS\system32\SgrmBroker.exe",
    "C:\WINDOWS\system32\msiexec.exe",
    "C:\WINDOWS\system32\SearchIndexer.exe"
)

function Determina-OrigemServico {
    param ($Caminho)

    if (-not $Caminho -or $Caminho -eq "") { return "Unknown" }

    $caminhoLower = $Caminho.ToLower()

    if ($caminhoLower -match "c:\\windows\\system32\\svchost.exe" -or 
        $servicosWindowsComuns -contains $Caminho) {
        return "Windows"
    } elseif ($caminhoLower -match "c:\\program files" -or 
              $caminhoLower -match "c:\\program files \\(x86\)") {
        return "Third"
    } else {
        return "Unknown"
    }
}

Write-Host "Processando serviÃ§os do sistema..."

$servicosFormatados = @()

foreach ($servico in $servicos) {
    $origem = Determina-OrigemServico -Caminho $servico.PathName

    $servico | Add-Member -MemberType NoteProperty -Name "Origem" -Value $origem -PassThru
    $servicosFormatados += $servico
}

if ($servicosFormatados.Count -eq 0) {
    Write-Host "Nenhum serviÃ§o encontrado." -ForegroundColor Yellow
    pause
    exit
}
cls
Write-Host "Exibindo lista de serviÃ§os..."

$servicosFormatados | Select-Object DisplayName, Name, State, StartMode, Origem, StartName, PathName | `
    Out-GridView -Title "SvcParser"

Write-Host "NOLW$" -ForegroundColor Green
                    Start-Sleep -Seconds 2
                    Write-Host "Script executado com sucesso!" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    cls
                    }
                    elseif ($Choser6 -eq 6) {
                    Write-Host "Operação cancelada."
                    Start-Sleep -Seconds 1
                    cls
                    }
                    else {
                    Write-Host "Opção inválida. Tente novamente."
                    Start-Sleep -Seconds 1  
                    cls  
                }
            }
            elseif ($Choser4 -eq 4) {
            cls
            Logo 
            Write-Host "Escolha uma Opção para Journal:"
            Write-Host ""
            Write-Host "        [1] JournalTrace"
            Write-Host "        [2] Echo JournalTool"
            Write-Host "        [3] Cancelar"
            Write-Host ""
        $ChoserJN = Read-Host "Digite o número da opção"

        if ($ChoserJN -eq 1) {
            Write-Host "Baixando JournalTrace"
            $urlJN = "https://github.com/spokwn/JournalTrace/releases/download/1.2/JournalTrace.exe"
            $destinationFileJN = "$OutfilePath\JournalTrace.exe"
            Invoke-WebRequest -Uri $urlJN -OutFile $destinationFileJN
            Write-Host "Download completo!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            cls
        }
        elseif ($ChoserJN -eq 2) {
            Write-Host "Baixando Echo JournalTool"
            $urlJN = "https://files.catbox.moe/u1txpf.bin"
            $destinationFileJN = "$OutfilePath\Journal-Tool.exe"
            Invoke-WebRequest -Uri $urlJN -OutFile $destinationFileJN
            Write-Host "Download completo!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            cls
        }
        elseif ($ChoserJN -eq 3) {
            Write-Host "Operação cancelada."
            Start-Sleep -Seconds 1
            cls
        }
        else {
            Write-Host "Opção inválida. Tente novamente."
            Start-Sleep -Seconds 1  
            cls  
        }
            }
            elseif ($Choser4 -eq 5) {
            Write-Host "Baixando InjGen"  
                    $url17 = "https://github.com/NotRequiem/InjGen/releases/download/v2.0/InjGen.exe"
                    $destinationFile17 = "$OutfilePath\InjGen.exe"
                    Invoke-WebRequest -Uri $url17 -OutFile $destinationFile17
                    Write-Host "Download completo!" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    cls
            }
            elseif ($Choser4 -eq 6) {
                Write-Host "Baixando EDDv310"  
                    $url18 = "https://files.catbox.moe/jqoeck.bin"
                    $destinationFile18 = "$OutfilePath\EDDv310.exe"
                    Invoke-WebRequest -Uri $url18 -OutFile $destinationFile18
                    Write-Host "Download completo!" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    Write-Host "Exec Disk Scan?"
                    Write-Host ""
                    Write-Host "        [1] Yes, Start scan;"
                    Write-Host "        [2] No, back to menu;"
                    Write-Host ""
                    $Choser7 = Read-Host "Digite o número da opção"
                    if ($Choser7 -eq 1) {
                    Start-Process cmd.exe -ArgumentList "/c `"$destinationFile18 /batch && echo ㅤ  && echo Disk Scan Complete && echo ㅤ && pause`"" -Verb RunAs
                    }
                    cls
            }
            elseif ($Choser4 -eq 7) {
            Write-Host "Baixando AppCompatCacheParser"
            $url15 = "https://download.ericzimmermanstools.com/AppCompatCacheParser.zip"
    
            if ([string]::IsNullOrEmpty($OutfilePath)) {
                $OutfilePath = "$env:USERPROFILE\Downloads"
                Write-Host "O caminho de saída não foi definido. Usando o caminho padrão: $OutfilePath" -ForegroundColor Yellow
            }
    
            $destinationFile15 = "$OutfilePath\AppCompatCacheParser.zip"
            $extractPath = "$OutfilePath\AppCompatCacheParser"
    
            Invoke-WebRequest -Uri $url15 -OutFile $destinationFile15
            Write-Host "Download completo!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            Write-Host ""
            Write-Host "Exec AppCompatCacheParser?"
            Write-Host ""
            Write-Host "        [1] Yes, Start AppCompatCacheParser;"
            Write-Host "        [2] No, back to menu;"
            Write-Host ""
            $userInput = Read-Host "Digite sua escolha"

            if ($userInput -eq '1') {
                if (!(Test-Path $extractPath)) {
                    New-Item -ItemType Directory -Path $extractPath | Out-Null
                }
                try {
                    Expand-Archive -Path $destinationFile15 -DestinationPath $extractPath -Force
                    Write-Host "Extração completa!" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    Write-Host ""
                    Start-Process cmd.exe -ArgumentList "/c cd `"AppCompatCacheParser`" && Appcompatcacheparser.exe --csv . & pause" -Verb RunAs
                } catch {
                    Write-Host "Erro: $_" -ForegroundColor Red
                }
            } else {
                Write-Host "Extração cancelada." -ForegroundColor Yellow
            }
    
            Start-Sleep -Seconds 1
            cls
        }
            elseif ($Choser4 -eq 8) {
                Write-Host "Baixando Velociraptor"  
                    $url16 = "https://github.com/Velocidex/velociraptor/releases/download/v0.73/velociraptor-v0.73.3-windows-amd64.exe"
                    $destinationFile16 = "$OutfilePath\Velociraptor.exe"
                    Invoke-WebRequest -Uri $url16 -OutFile $destinationFile16
                    Write-Host "Download completo!" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    Write-Host "Exec Velociraptor GUI?"
                    Write-Host ""
                    Write-Host "        [1] Yes, Start Velociraptor GUI;"
                    Write-Host "        [2] No, back to menu;"
                    Write-Host ""
                    $Choser8 = Read-Host "Digite o número da opção"
                    if ($Choser8 -eq 1) {
                    Start-Process cmd.exe -ArgumentList "/c `"$destinationFile16 gui`"" -Verb RunAs
                    }
                    cls
            }
              elseif ($Choser4 -eq 9) {
                Write-Host "Baixando Unicode"  
                    $url19 = "https://github.com/RRancio/unicode/releases/download/rel/Unicode.exe"
                    $destinationFile19 = "$OutfilePath\Unicode.exe"
                    Invoke-WebRequest -Uri $url19 -OutFile $destinationFile19
                    Write-Host "Download completo!" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    cls
            }
            elseif ($Choser4 -eq 0){
            cls
            Logo
                Write-Host "Executando Service Check" -ForegroundColor Cyan

    Write-Host ""
    Write-Host "=============SERVICES============="
    Write-Host ""
    $services = @("Appinfo", "Cdpusersvc", "Diagtrack", "Dusmsvc", "DPS", "Eventlog", "Pcasvc", "Sgrmbroker", "Sysmain", "BAM")

    foreach ($serviceName in $services) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            if ($service.Status -eq 'Running') {
                Write-Host "Running" -ForegroundColor Green -NoNewline
            } else {
                Write-Host "Disable" -ForegroundColor Red -NoNewline
            }
            Write-Host " $serviceName" -ForegroundColor Yellow
        } else {
            Write-Host "Serviço não encontrado: <$serviceName>" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
    Write-Host "Service Check completo!" -ForegroundColor Green
    Start-Sleep -Seconds 1
    Write-Host ""
    Write-Host "Pressione Enter para continuar..." -ForegroundColor Cyan
    Read-Host
    cls
}
            elseif ($Choser4 -match "^exit$") {
            Write-Host "Saindo..." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            cd C:\Windows\System32
            cls
            cmd
            exit  
            }
            elseif ($Choser4 -match "^back$") {
            Write-Host "Voltando ao Menu Principal..." -ForegroundColor Yellow
            break  
            cls
        }
        else {
            Write-Host "Opção inválida. Tente novamente." -ForegroundColor Red
            Start-Sleep -Seconds 1
            cls
        }
    } while ($true) 
    if ($Choser -match "^next$") {
        cls  
    }
}
    elseif ($Choser -match "^exit$") {
        cls
        Logo
        Write-Host "Saindo..." -ForegroundColor Yellow
        Start-Sleep -Seconds 1 
        cls
        cd C:\Windows\System32
        cmd
        break
        cls
    }
    else {
        Write-Host "Opção inválida. Tente novamente."
        Start-Sleep -Seconds 1  
        cls
    }
    MainMenu
}
