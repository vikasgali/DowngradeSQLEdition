#SQL Creds to run commands on SQL Server. Its recommended to use Windows Authentication
$SQLUsername = '{{SQLUsername}}'
$SQLPasswordSSM='{{PasswordSSMParameter}}'
$SQLPassword= (Get-SSMParameterValue -Name $SQLPasswordSSM -WithDecryption:$true).Parameters[0].Value | ConvertTo-SecureString -AsPlainText -Force
#Backup location where you want your backups to go
$backuplocation= '{{backuplocation}}'
#S3 location for SQL installation Media and ConfigurationFile
$S3BucketName = '{{S3BucketName}}'
#S3 location for SQL CU
#$S3CUBucketName = (Get-SSMParameterValue -Name S3CUBucketName).Parameters[0].Value
$S3CUName = '{{S3CUName}}'
$saPwdSSM ='{{saPwdSSMParameter}}'
$saPwd= (Get-SSMParameterValue -Name $saPwdSSM -WithDecryption:$true).Parameters[0].Value | ConvertTo-SecureString -AsPlainText -Force
$timeStamp = Get-Date -format yyyy_MM_dd_HHmmss
Write-Host $SQLUsername
Write-Host $backuplocation
Write-Host $S3BucketName
Write-Host $S3CUName
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $SQLUsername, $SQLPassword
#Get-Credential -Credential $Cred
#Create a new PowerShell session in the security context of the alternate user, using the PSCredential object we just created
$RunasDifferentUser= New-PSSession -Credential $cred;
Invoke-Command -Session $RunasDifferentUser -Script {
# Write-Host $env:userdomain\$env:username
function Write-Log
{
PARAM
(
[Parameter(Mandatory = $true)] [string] $Message
,[ValidateSet("Green", "Yellow", "Red")] [string] $Color
)
$Datestamp = [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss.fff')
$CompleteMessage = "$Datestamp $Message"
if($Color)
{
Write-Host $CompleteMessage -ForegroundColor $Color
}
else
{
Write-Host $CompleteMessage
}
Write-Output $CompleteMessage | out-file -encoding ASCII $LogFile -Append
}
$DestinationDriveFolder="C:\Windows\temp"
$LogFile = $DestinationDriveFolder + "\Logfile.txt"

if (Test-Path $LogFile)
{
Remove-Item -Path $LogFile
New-Item -path $LogFile
Write-Log "New Log File Created"
}
$pendingRebootTests = @(
@{
Name = 'RebootPending'
Test = { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'  -Name 'RebootPending' -ErrorAction Ignore }
TestType = 'ValueExists'
}
@{
Name = 'RebootRequired'
Test = { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'  -Name 'RebootRequired' -ErrorAction Ignore }
TestType = 'ValueExists'
}
@{
Name = 'PendingFileRenameOperations'
Test = { Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction Ignore }
TestType = 'NonNullValue'
}
)
foreach ($test in $pendingRebootTests) {
$result = Invoke-Command -ScriptBlock $test.Test
if ($test.TestType -eq 'ValueExists' -and $result) {
Write-log "Reboot Required, restart after rebooting server"
Throw
} elseif ($test.TestType -eq 'NonNullValue' -and $result -and $result.($test.Name)) {
Write-log "Reboot Required, restatt after rebooting server"
Throw
} else {
Write-log "No pending Reboot, proceeding with next check"
}
}
$TotalInstanceServices=Get-Service | Where-Object {$_.DisplayName -like "SQL Server (*"}
If ($TotalInstanceServices.Count -gt 1)
{
Write-Log "Multiple SQL Instances are Installed on this Server.Not supported at this time" -Color Red
Throw
}
elseif ($TotalInstanceServices.Count -eq 0)
{
Write-Log "SQL is not installed on this machine" -Color Red
Throw
}
$InstanceService= $TotalInstanceServices.Name

#Check Whether Enterprise Edition is installed or not
$InstanceName= (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server').InstalledInstances
$InstanceID=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -Name $InstanceName
$Edition = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\${InstanceID}\Setup" -Name 'Edition'
$Port=Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\${InstanceID}\MSSQLServer\SuperSocketNetLib\Tcp\IPAll" -Name "TcpPort"
if ($Edition -notlike '*Enterprise*')
{
Write-Log "It's not Enterprise Edition.No Need to run script to downgrade" -Color Red
Throw
}
else
{
Write-Log "Checking whether sql is running or not" -Color Green
}
#Get Current Time Stamp
#Check If SQL Server is Running or not
$status =get-service $InstanceService | select Status
#Get SQL Server Instance Name
If ($InstanceName -eq 'MSSQLSERVER')
{
$SQLInstanceName ="."
Write-Host $SQLInstanceName
}
else
{
$SQLInstancenName="localhost\"+$InstanceName+','+ $Port
Write-Host $SQLInstanceName
}
If($status.Status -eq "Running")
{
Write-Log "SQLServer is Running"
#Check If SQL Server is Clustered or not
[array]$Clustered = Invoke-Sqlcmd -ServerInstance $SQLInstancenName -Query "select  SERVERPROPERTY('IsClustered') as IsClustered,SERVERPROPERTY('IsHadrEnabled') as IsHadrEnabled" #-Credential $Cred
if($Clustered.isClustered -eq 1 -or $Clustered.IsHadrEnabled -eq 1)
{
Write-Log "SQL is clustered or Part of Always on Availability Groups. Not supported at this time" -Color Red
Throw
}
}
else
{
Write-Log "SQLServer is not Running"
Throw
}
$DiskSize=Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"| Select-Object Size,FreeSpace
if($DiskSize.FreeSpace/1GB -gt 4)
{
Write-Log "Enough Space to download SQL Media on C drive" -Color Green
}
else
{
Write-Log "Not Enough Space to download SQL Media on C drive" -Color Red
Throw
}
Write-Log "Starting SQL Binaries Download"
$SQLInstallationFolder="C:\SQL" + "_" + $using:timeStamp
Write-Log $SQLInstallationFolder
New-Item -ItemType directory $SQLInstallationFolder
Read-S3Object -BucketName $using:S3BucketName -KeyPrefix * -Folder $SQLInstallationFolder
#Check Whether Installation is Mixed Authentication and look for SA Password####
 $SQLInstallationFolder=$SQLInstallationFolder+ "\SQLinstall"
 $InstallPath=$SQLInstallationFolder
 $SecurityPattern='SECURITYMODE="SQL"'
 $SecurityMode=Get-Content "${InstallPath}\ConfigurationFile.ini" |  Select-String -Pattern 'SECURITYMODE="SQL"'
 Write-Host $SecurityMode
 if ([string]::IsNullOrWhiteSpace($SecurityMode))
 {
 Write-log "Windows Authentication mode installation"   -Color Green
 Write-Host $InstallPath
 $installaction="/ACTION=""Install"" /Q /IAcceptSqlServerLicenseTerms /configurationfile=""$SQLInstallationFolder\ConfigurationFile.ini"""
 Write-Host $action
 }
 else
 {
 if ([string]::IsNullOrWhiteSpace($using:SaPwd))
 {
 Write-log "Create Parameter for SA Password "   -Color Red
 }
 else
 {
 Write-log "Mixed Authentication mode installation"
  $BSTR = `
  [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Using:saPWD)
  $sa = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

 $installaction="/ACTION=""Install"" /Q /IAcceptSqlServerLicenseTerms /SAPWD=""${sa}"" /configurationfile=""${SQLInstallationFolder}\ConfigurationFile.ini"""
 }
 }
 #GET DB File Location (we are getting this info ,Uninstalling SQL will not remove tempdb files if they are in custom location)
 [array]$TempDBFileLocation = Invoke-Sqlcmd -ServerInstance $SQLInstancenName -Query "USE tempdb;
                         SELECT
                        physical_name
                        FROM sys.database_files;"
 $TempDBFileLocation.physical_name
 #User Database File location
 $userdbnames=Invoke-Sqlcmd -ServerInstance $SQLInstancenName -Query "SELECT
             DataFile.database_id,
             DataFile.name,
             DataFile.physical_name as DataFile,
             LogFile.physical_name as LogFile
            FROM (SELECT * FROM sys.master_files WHERE type_desc = 'ROWS' ) DataFile
         JOIN (SELECT * FROM sys.master_files WHERE type_desc = 'LOG' ) LogFile
         ON DataFile.database_id = LogFile.database_id
         where DataFile.database_id>4;"

 #Get list of all Databases and backup them
 Write-host $using:backuplocation
 Write-host $using:timestamp
 $backupfolder = $using:backuplocation + "\" + $using:timeStamp
 Write-host $backupfolder
 if (Test-Path $backupfolder)
 {
 Write-Log "Folder Already Exists"
 }
 else{
 New-Item -path $backupfolder -ItemType Directory
 Write-Log "Backup Folder Created"
 }
 # New-Item -Path $backuplocation\$timeStamp -ItemType Directory
 # $backupdevice=$backuplocation+"\"+ $backupfolder.Name
 #GET DB File Location (we are getting this info ,Uninstalling SQL will not remove tempdb files if they are in custom location)
 [array]$TempDBFileLocation = Invoke-Sqlcmd -ServerInstance $SQLInstancenName -Query "USE tempdb;
                         SELECT
                        physical_name
                         FROM sys.database_files;"
 $TempDBFileLocation.physical_name
 #User Database File location
 $userdbfilepath=$backupfolder+'\userdatabase_path.csv'


 $SQLPathCOMMAND="SET NOCOUNT ON
 DECLARE     @cmd        VARCHAR(MAX),
 @dbname     VARCHAR(200),
 @prevdbname VARCHAR(200)
 SELECT @cmd = '', @dbname = ';', @prevdbname = ''
 CREATE TABLE #Attach
 (Seq        INT IDENTITY(1,1) PRIMARY KEY,
 dbname     SYSNAME NULL,
 fileid     INT NULL,
 filename   VARCHAR(1000) NULL,
 TxtAttach  VARCHAR(MAX) NULL
 )
 INSERT INTO #Attach
 SELECT DISTINCT DB_NAME(dbid) AS dbname, fileid, filename, CONVERT(VARCHAR(MAX),'') AS TxtAttach
 FROM master.dbo.sysaltfiles
 WHERE dbid IN (SELECT dbid FROM master.dbo.sysaltfiles )
 AND DATABASEPROPERTYEX( DB_NAME(dbid) , 'Status' ) = 'ONLINE'
 AND DB_NAME(dbid) NOT IN ('master','tempdb','msdb','model')
 ORDER BY dbname, fileid, filename
 UPDATE #Attach
 SET @cmd = TxtAttach =
 CASE WHEN dbname <> @prevdbname
 THEN CONVERT(VARCHAR(200),'exec sp_attach_db @dbname = N''' + dbname + '''')
 ELSE @cmd
 END +',@filename' + CONVERT(VARCHAR(10),fileid) + '=N''' + filename +'''',
 @prevdbname = CASE WHEN dbname <> @prevdbname THEN dbname ELSE @prevdbname END,
 @dbname = dbname
 FROM #Attach  WITH (INDEX(0),TABLOCKX)
 OPTION (MAXDOP 1)
 SELECT dbname,TxtAttach
 from
 (SELECT dbname, MAX(TxtAttach) AS TxtAttach FROM #Attach
 GROUP BY dbname) AS x
 DROP TABLE #Attach
 GO"
 $userdbpathoutput=invoke-sqlcmd -ServerInstance "." -query $SQLPathCOMMAND | Export-Csv -Path $userdbfilepath -NoTypeInformation
 $GetDBNames = Get-SqlDatabase -ServerInstance $SQLInstanceName | Where { $_.Name -ne 'tempdb' }
 $dbnames= $GetDBNames.Name
 Foreach ($Db in $dbnames)
 {
 try
 {
 Write-log "Backup Started for $Db" -Color Green
 $backupFullPath=$backupfolder + "\" + $Db + "_" + $using:timeStamp + ".bak"
 Backup-SqlDatabase -ServerInstance $SQLInstanceName -Database $Db -BackupFile $backupFullPath
 Write-log "Backup Finished for $Db" -Color Green
 }
 Catch
 {
 Write-log "Backup Failed for $Db"   -Color Red
 write-log ($Error[0].Exception)
 Throw
 }
 }
 Write-Log "System Databases file copy started"
$systemfiles=Invoke-sqlcmd -ServerInstance $SQLInstancenName -Query "select filename from sysaltfiles where dbid in (1,4)"
$ServiceName=(Get-Service | Where-Object {$_.DisplayName -like "SQL Server (*"}).Name
Stop-Service -Force $ServiceName
$files=$systemfiles.filename
foreach ($file in $files)
{
Write-Log "Copying file ${file}"
Copy-Item -Path $file -Destination $backupfolder\

}


 #Setup File Location
 $setupfileLocation = Get-ChildItem -Recurse -Include setup.exe -Path "$env:ProgramFiles\Microsoft SQL Server" -ErrorAction SilentlyContinue |
 Where-Object { $_.FullName -match 'Setup Bootstrap\\SQL' -or $_.FullName -match 'Bootstrap\\Release\\Setup.exe' -or $_.FullName -match 'Bootstrap\\Setup.exe' } |
 Sort-Object FullName -Descending | Select-Object -First 1
 $DirectoryName=$setupfileLocation.DirectoryName
 #Stop-Service $ServiceName -Force
 Write-Log "SQL Service has been stopped" -Color Green
 Write-log "SQL Uninstallation Started"   -Color Green
 $Path=$DirectoryName
 $uninstallaction="/ACTION=""unInstall"" /Q /FEATURES=SQL,AS,RS,IS,Tools /InstanceName=${InstanceName}"
 Start-Process -WorkingDirectory $Path setup.exe  $uninstallaction -Verb runAs -Wait
 #Delete Orphan tempdb files
 foreach ($file in $TempDBFileLocation.physical_name)
 {
 Remove-Item  $file -Force
 Write-Log "$file is removed"
 }
 $SQLErrorLogFile=Split-Path $setupfileLocation.DirectoryName
 $SQLErrorLogFileLocation=$SQLErrorLogFile + "\Log\Summary.txt"
 $CheckError = Select-String -Path $SQLErrorLogFileLocation -Pattern "Failed: see details below"
 if ([string]::IsNullOrWhiteSpace($CheckError))
 {
 Write-log "SQL Uninstalled Successfully"   -Color Green
 }else
 {
 Write-log "SQL Uninstallation failed"   -Color Red
 Throw
 }
 Write-log "SQL Installation Started"   -Color Green
 #Install SQL Server
 # Add  /PID for Product key
 #/SQLSVCPASSWORD="password" /ASSVCPASSWORD="password" /AGTSVCPASSWORD="password" /ISSVCPASSWORD="password" /RSSVCPASSWORD="password" /SAPWD="password" /ConfigurationFile=ConfigurationFile.INI
 #change the config file settings to your file name
 Write-Host $InstallPath
 Write-Host $installaction
 Start-Process -FilePath "setup.exe" -WorkingDirectory $InstallPath $installaction -Wait
 }
 Invoke-Command -Session $RunasDifferentUser -Script{
 function Write-Log
 {
 PARAM
 (
 [Parameter(Mandatory = $true)] [string] $Message
 ,[ValidateSet("Green", "Yellow", "Red")] [string] $Color
 )
 $Datestamp = [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss.fff')
 $CompleteMessage = "$Datestamp $Message"
 if($Color)
 {
 Write-Host $CompleteMessage -ForegroundColor $Color
 }
 else
 {
 Write-Host $CompleteMessage
 }
 Write-Output $CompleteMessage | out-file -encoding ASCII $LogFile -Append
 }
 $DestinationDriveFolder="C:\Windows\temp"
 $LogFile = $DestinationDriveFolder + "\LogfileCU.txt"
 if (Test-Path $LogFile)
 {
 Remove-Item -Path $LogFile
 New-Item -path $LogFile
 Write-Log "New Log File Created"
 }
 #Setup File Location
 $setupfileLocation = Get-ChildItem -Recurse -Include setup.exe -Path "$env:ProgramFiles\Microsoft SQL Server" -ErrorAction SilentlyContinue |
 Where-Object { $_.FullName -match 'Setup Bootstrap\\SQL' -or $_.FullName -match 'Bootstrap\\Release\\Setup.exe' -or $_.FullName -match 'Bootstrap\\Setup.exe' } |
 Sort-Object FullName -Descending | Select-Object -First 1
 $DirectoryName=$setupfileLocation.DirectoryName
 $Path=$DirectoryName
 $SQLErrorLogFile=Split-Path $setupfileLocation.DirectoryName
 $SQLErrorLogFileLocation=$SQLErrorLogFile + "\Log\Summary.txt"
 $Reboot = Get-WmiObject -Class win32_operatingsystem
 $RebootDT=$Reboot.ConvertToDateTime($Reboot.LastBootUpTime)
 $Rebootformatted=$RebootDT.ToString("MM/dd/yyyy hh:mm tt")
 $Summary=Get-Item $SQLErrorLogFileLocation
 $Summarytime=$Summary.LastWritetime.ToString("MM/dd/yyyy hh:mm tt")
 $SQLInstallationFolder="C:\SQL" + "_" + $using:timeStamp
 $SQLInstallationFolder=$SQLInstallationFolder+"\CU"
 Write-Host $SQLInstallationFolder
 $Path=$SQLInstallationFolder
 $updateaction="/ACTION=""Patch"" /Q /IAcceptSqlServerLicenseTerms /AllInstances"
 Write-host $updateaction
 $CheckError = Select-String -Path $SQLErrorLogFileLocation -Pattern "Failed: see details below","Passed but reboot required, see logs for details"
 Write-Host $CheckError
 if ([string]::IsNullOrWhiteSpace($CheckError))
 {
 Write-log "SQL Installed Successfully"   -Color Green
 Write-Host $using:S3CUName
 if ([string]::IsNullOrWhiteSpace($using:S3CUName))
 {
 Write-Log "There is no Cummulative Update to apply"
 }
 else{
 #Install SQL Server CU
 #/SQLSVCPASSWORD="password" /ASSVCPASSWORD="password" /AGTSVCPASSWORD="password" /ISSVCPASSWORD="password" /RSSVCPASSWORD="password" /SAPWD="password" /ConfigurationFile=ConfigurationFile.INI
 #change the config file settings to your file name
 Start-Process -WorkingDirectory $Path -FilePath $using:S3CUName  $updateaction -Wait
 }
 }
 else
 {
 if ($Rebootformatted -gt $Summarytime)
 {
 Write-Host "Reboot has occured after last failed attempt"
 Start-Process -WorkingDirectory $Path -FilePath $using:S3CUName  $updateaction -Wait
 }
 else{
 Write-log "SQL Installation failed or Reboot Required"   -Color Red
 Throw
 }
 }
 }


 Write-Log "Restore Database"
 Invoke-Command -Session $RunasDifferentUser -Script{

 $backupfolder = $using:backuplocation + "\" + $using:timeStamp
 $userdbfilepath=$backupfolder+'\userdatabase_path.csv'
 $InstanceName= (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server').InstalledInstances
 $InstanceID=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -Name $InstanceName
 $Edition = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\${InstanceID}\Setup" -Name 'Edition'
 function Write-Log
 {
 PARAM
 (
 [Parameter(Mandatory = $true)] [string] $Message
 ,[ValidateSet("Green", "Yellow", "Red")] [string] $Color
 )
 $Datestamp = [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss.fff')
 $CompleteMessage = "$Datestamp $Message"
 if($Color)
 {
 Write-Host $CompleteMessage -ForegroundColor $Color
 }
 else
 {
 Write-Host $CompleteMessage
 }
 Write-Output $CompleteMessage | out-file -encoding ASCII $LogFile -Append
 }
 $DestinationDriveFolder="C:\Windows\temp"
 $LogFile = $DestinationDriveFolder + "\LogfileRestore.txt"
 if (Test-Path $LogFile)
 {
 Remove-Item -Path $LogFile
 New-Item -path $LogFile
 Write-Log "New Log File Created"
 }
 if ($Edition -like '*Enterprise*')
 {
 Write-Log "SQL Server downgrade was not succesful" -Color Red
 Throw
 }
 else
 {
 Write-Log "Checking whether sql is running or not" -Color Green
 }
 #Get Current Time Stamp
 $InstanceService=Get-Service | Where-Object {$_.DisplayName -like "SQL Server (*"}
 $InstService=$InstanceService.Name
 #Check If SQL Server is Running or not
 $status =get-service $InstanceService.Name | select Status
 If($status.Status -eq "Running")
 {
 Write-Log "SQLServer is Running" -Color Green
 #Check If SQL Server is Clustered or not
 [array]$Clustered = Invoke-Sqlcmd -Query "select  SERVERPROPERTY('IsClustered') as IsClustered,SERVERPROPERTY('IsHadrEnabled') as IsHadrEnabled" #-Credential $Cred
 if($Clustered.isClustered -eq 1 -or $Clustered.IsHadrEnabled -eq 1)
 {
 Write-Log "SQL is clustered or Part of Always on Availability Groups. Not supported at this time" -Color Red
 Throw
 }
 }
 else
 {
 Write-Log "SQLServer is not Running" -Color Red
 Throw
 }
 If ($InstanceName ='MSSQLSERVER')
 {
 $SQLInstanceName ="."
 }
 else
 {
 $SQLInstancenName="localhost\"+$InstanceName
 }
 Import-CSV $userdbfilepath | ForEach-Object {
 #Current row object
 $CSVRecord = $_
 $attachcmd2 = $CSVRecord.'TxtAttach'
 Write-Host $attachcmd2
 try
 {
 Invoke-sqlcmd -ServerInstance $SQLInstanceName -Query $attachcmd2 -QueryTimeout 3600
 }
 Catch
 {
 Write-Log "Database attachment Failed for ${dbname}" -Color Red
 write-Host ($Error[0].Exception)
 Throw
 }
 }

$newsystemfiles=(Invoke-sqlcmd -ServerInstance $SQLInstanceName -Query "select filename from sysaltfiles where dbid in (1,4)").filename
Stop-Service  $InstService

foreach ($newsystemfile in $newsystemfiles){

$newfilename=$newsystemfile+'_old'
Rename-Item -Path $newsystemfile -NewName $newfilename
$pathpos=$newsystemfile.LastIndexOf("\")
$dbfilepos=($newsystemfile.length - $pathpos -1)
$systempath=$newsystemfile.Substring(0,$pathpos+1)
$dbfilename=$newsystemfile.SubString($newsystemfile.length - $dbfilepos)
$oldfile= (Get-ChildItem $backupfolder -Recurse -Include $dbfilename).name
Write-Log "Copying System databases files"
Copy-Item -Path $backupfolder\$oldfile -Destination $systempath\
}
Write-Log "Starting SQL Server "
Start-Service $InstService


 }