@ECHO OFF
SETLOCAL EnableDelayedExpansion
:: Eseguire come Amministratore




:: ########################################################################
:: 1. CREAZIONE PUNTO DI RIPRISTINO
:: ########################################################################
powershell.exe enable-computerrestore -drive c:\
powershell.exe -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'BeforeSecurityHardening' -RestorePointType 'MODIFY_SETTINGS'"




:: ########################################################################
:: 2. PROTEZIONE MICROSOFT OFFICE (Anti-Malware/Macro)
:: ########################################################################
:: Blocca OLE e imposta avvisi per macro e contenuti esterni
for %%v in (12.0 14.0 15.0 16.0) do (
    reg add "HKCU\Software\Policies\Microsoft\Office\%%v\Word\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
    reg add "HKCU\Software\Policies\Microsoft\Office\%%v\Excel\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
    reg add "HKCU\Software\Policies\Microsoft\Office\%%v\PowerPoint\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
    reg add "HKCU\SOFTWARE\Microsoft\Office\%%v\Word\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
    reg add "HKCU\SOFTWARE\Microsoft\Office\%%v\Word\Security" /v AllowDDE /t REG_DWORD /d 0 /f
)
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\Security" /v DisableAllActiveX /t REG_DWORD /d 1 /f




:: ########################################################################
:: 3. CONFIGURAZIONE AVANZATA WINDOWS DEFENDER (ASR Rules)
:: ########################################################################
:: Abilita la sandbox e la protezione PUA
setx /M MP_FORCE_USE_SANDBOX 1
powershell.exe Set-MpPreference -PUAProtection enable
powershell.exe Set-MpPreference -EnableNetworkProtection Enabled
powershell.exe Set-MpPreference -EnableControlledFolderAccess Enabled


:: Regole Attack Surface Reduction (ASR)
:: Blocca furto credenziali LSASS
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
:: Blocca processi da USB
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled
:: Blocca chiamate Win32 API da macro Office
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
:: Blocca script offuscati
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled


powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
:: Esempio: Audit dei tentativi di accesso falliti
auditpol /set /subcategory:"Logon" /failure:enable
:: Forza UAC al livello massimo (Prompt for credentials on the secure desktop)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 1 /f




:: ########################################################################
:: 4. SICUREZZA DI RETE E SERVIZI
:: ########################################################################
:: Disabilita protocolli obsoleti e rischiosi (SMBv1, NetBIOS, DNS Multicast)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
:: Disabilita compressione SMBv3 (Mitigazione CVE-2020-0796)
powershell.exe Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force
:: Abilita log per connessioni bloccate e consentite
netsh advfirewall set allprofiles logging droppedconnections enable
:: netsh advfirewall set allprofiles logging allowedconnections enable
:: Disabilita LLMNR
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d 0 /f
:: Disabilita NetBIOS su TCP/IP (richiede identificazione dell'interfaccia, operazione complessa via batch)




:: ########################################################################
:: 5. PROTEZIONE ESTENSIONI FILE (Associazione a Notepad)
:: ########################################################################
:: Evita l'esecuzione accidentale di script comuni trasformandoli in file di testo
assoc .vbs=txtfile
assoc .vbe=txtfile
assoc .js=txtfile
assoc .jse=txtfile
assoc .hta=txtfile
assoc .wsh=txtfile
assoc .wsf=txtfile
assoc .ps1=txtfile
ftype vbsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%%1"
ftype wshfile="%SystemRoot%\system32\NOTEPAD.EXE" "%%1"




:: ########################################################################
:: 6. MITIGAZIONI DI SISTEMA (Exploit Protection)
:: ########################################################################
:: Abilita DEP e altre protezioni di sistema
powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError




ECHO Hardening completato. Riavvio del sistema.
shutdown -r -t 0