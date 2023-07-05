
            #Windows downgrade user secrets

            $UserSecret = '{{DowngradeUserSecret}}'
            #SQL Creds to run commands on SQL Server. Its recommended to use Windows Authentication
            $SQLUsername =  Get-SECSecretValue -SecretId $UserSecret -Select SecretString | ConvertFrom-Json | Select -ExpandProperty username 
            $SQLPwd= Get-SECSecretValue -SecretId $UserSecret -Select SecretString | ConvertFrom-Json | Select -ExpandProperty password
            $SQLpassword = ConvertTo-SecureString $SQLpwd -AsPlainText -Force 
            #Backup location where you want your backups to go
            $backuplocation= '{{backuplocation}}'
            #S3 location for SQL installation Media and ConfigurationFile
            $S3BucketName = '{{S3BucketName}}'
            #S3 location for SQL CU
            #$S3CUBucketName = (Get-SSMParameterValue -Name S3CUBucketName).Parameters[0].Value 
            $S3CUName = '{{S3CUName}}'
            $saPwdSSM ='{{saPwdSecret}}'
            $saPwd= Get-SECSecretValue -SecretId $saPwdSSM -Select SecretString | ConvertFrom-Json | Select -ExpandProperty password
            $timeStamp = Get-Date -format yyyy_MM_dd_HHmmss 
            Write-Host $SQLUsername
            Write-Host $backuplocation
            Write-Host $S3BucketName
            Write-Host $S3CUName
            $cred = New-Object System.Management.Automation.PSCredential ($SQLUsername, $SQLpassword) 
            #Get-Credential -Credential $Cred
            #Create a new PowerShell session in the security context of the alternate user, using the PSCredential object we just created            
            $RunasDifferentUser= New-PSSession -ComputerName EC2AMAZ-UTIADV5.massmigration.com -Credential $cred ; 
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
            [array]$Clustered = Invoke-Sqlcmd -ServerInstance $SQLInstancenName -Query "select  SERVERPROPERTY('IsClustered') as IsClustered,SERVERPROPERTY('IsHadrEnabled') as IsHadrEnabled" -TrustServerCertificate #-Credential $Cred
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
            $DiskSize=Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='D:'"| Select-Object Size,FreeSpace
            if($DiskSize.FreeSpace/1GB -gt 4)
            {
            Write-Log "Enough Space to download SQL Media on D drive" -Color Green
            }
            else
            {
            Write-Log "Not Enough Space to download SQL Media on D drive" -Color Red
            Throw
            }
            Write-Log "Starting SQL Binaries Download"
            $SQLInstallationFolder="D:\SQL" + "_" + $using:timeStamp
            Write-Log $SQLInstallationFolder
            New-Item -ItemType directory $SQLInstallationFolder
            Read-S3Object -BucketName $using:S3BucketName -KeyPrefix * -Folder $SQLInstallationFolder

            #Check Whether Installation is Mixed Authentication and look for SA Password####
             $SQLInstallationFolder=$SQLInstallationFolder+ "\SQLinstall"
             $InstallPath=$SQLInstallationFolder
             $SecurityPattern='SECURITYMODE="SQL"'
             $SecurityMode=Get-Content "${InstallPath}\ConfigurationFile_WithAllSettingsFinal.ini" |  Select-String -Pattern 'SECURITYMODE="SQL"'
             Write-Host $SecurityMode
             if ([string]::IsNullOrWhiteSpace($SecurityMode)) 
             {
             Write-log "Windows Authentication mode installation"   -Color Green
             Write-Host $InstallPath
             $installaction="/ACTION=""Install"" /Q /IAcceptSqlServerLicenseTerms /configurationfile=""$SQLInstallationFolder\ConfigurationFile_WithAllSettingsFinal.ini""" 
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
             $sa=$using:saPWD
             $installaction="/ACTION=""Install"" /Q /IAcceptSqlServerLicenseTerms /SAPWD=$sa /configurationfile=""${SQLInstallationFolder}\ConfigurationFile_WithAllSettingsFinal.ini""" 
             }
             }
             #GET DB File Location (we are getting this info ,Uninstalling SQL will not remove tempdb files if they are in custom location)
             [array]$TempDBFileLocation = Invoke-Sqlcmd -ServerInstance $SQLInstancenName -Query "USE tempdb;
                                     SELECT 
                                    physical_name
                                    FROM sys.database_files;" -TrustServerCertificate
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
                     where DataFile.database_id>4;"  -TrustServerCertificate
                             
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
                                     FROM sys.database_files;" -TrustServerCertificate
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
             $userdbpathoutput=invoke-sqlcmd -ServerInstance "." -query $SQLPathCOMMAND -TrustServerCertificate| Export-Csv -Path $userdbfilepath -NoTypeInformation
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
             
            $systemfiles=Invoke-sqlcmd -ServerInstance $SQLInstancenName -Query "select filename from sysaltfiles where dbid in (1,3,4)" -TrustServerCertificate
            $ServiceName=(Get-Service | Where-Object {$_.DisplayName -like "SQL Server (*"}).Name 
            Stop-Service -Force $ServiceName
            $files=$systemfiles.filename
            foreach ($file in $files)
            {
            Copy-Item -Path $file -Destination $using:backuplocation\

            } 

             
             #Setup File Location
             $setupfileLocation = Get-ChildItem -Recurse -Include setup.exe -Path "$env:ProgramFiles\Microsoft SQL Server" -ErrorAction SilentlyContinue |
             Where-Object { $_.FullName -match 'Setup Bootstrap\\SQL' -or $_.FullName -match 'Bootstrap\\Release\\Setup.exe' -or $_.FullName -match 'Bootstrap\\Setup.exe' } |
             Sort-Object FullName -Descending | Select-Object -First 1
             $DirectoryName=$setupfileLocation.DirectoryName
             Stop-Service $ServiceName -Force
             Write-Log "SQL Service has been stopped" -Color Green
             Write-log "SQL Uninstallation Started"   -Color Green
             $Path=$DirectoryName
             $uninstallaction="/ACTION=""unInstall"" /Q /FEATURES=SQL,AS,RS,IS,Tools /InstanceName=${InstanceName}"
             Start-Process -WorkingDirectory $Path setup.exe  $uninstallaction -Verb runAs -Wait
             #Delete Orphan tempdb files
             foreach ($file in $TempDBFileLocation.physical_name)
             {
             if (Test-Path $file)
             {
             Remove-Item  $file -Force
             Write-Log "$file is removed"
             }
             else {Write-Log "$file is removed"
             }
             }
             $SQLErrorLogFile=Split-Path $setupfileLocation.DirectoryName
             $SQLErrorLogFileLocation=$SQLErrorLogFile + "\Log\Summary.txt"
             $CheckError = Select-String -Path $SQLErrorLogFileLocation -Pattern "Failed: see details below"
             if ([string]::IsNullOrWhiteSpace($CheckError)) 
             {
             Write-log "SQL Uninstalled Successfully"   -Color Green

             #######Check for Reboot Requirement
             $CheckReboot = Select-String -Path $SQLErrorLogFileLocation -Pattern "Passed but reboot required, see logs for details"
             if ([string]::IsNullOrWhiteSpace($CheckError)) 
             {
             Write-log "No reboot required and Proceed with Installation"   -Color Green
             Start-Process -FilePath "setup.exe" -WorkingDirectory $InstallPath $installaction -Wait
             }
             else 
             {
             Write-log "Reboot Required before Installation"   -Color Red
             EXIT 3010

             }
             }
             else 
             {
             Write-log "SQL Uninstallation failed"   -Color Red
             Throw
             }

             
             } 


             #############################<# SQL Install after reboot #>######################################

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
            $LogFile = $DestinationDriveFolder + "\Logfile_Reboot.txt"

            if (Test-Path $LogFile)
            {
            Remove-Item -Path $LogFile
            New-Item -path $LogFile
            Write-Log "New Log File Created"
            }



            ###Check Whether SQL is already installed#############

            $TotalInstanceServices=Get-Service | Where-Object {$_.DisplayName -like "SQL Server (*"} 
            If ($TotalInstanceServices.Count -eq 0)
            {
            Write-Log "Proceeding with SQL Install" -Color Green
            #Check Whether Installation is Mixed Authentication and look for SA Password####
             $SQLInstallationFolder="D:\SQL" + "_" + $using:timeStamp
             $SQLInstallationFolder=$SQLInstallationFolder+ "\SQLinstall"
             $InstallPath=$SQLInstallationFolder
             $SecurityPattern='SECURITYMODE="SQL"'
             $SecurityMode=Get-Content "${InstallPath}\ConfigurationFile_WithAllSettingsFinal.ini" |  Select-String -Pattern 'SECURITYMODE="SQL"'
             
             Write-Host $SecurityMode
             if ([string]::IsNullOrWhiteSpace($SecurityMode)) 
             {
             Write-log "Windows Authentication mode installation"   -Color Green
             Write-Host $InstallPath
             $installaction="/ACTION=""Install"" /Q /IAcceptSqlServerLicenseTerms /configurationfile=""$SQLInstallationFolder\ConfigurationFile_WithAllSettingsFinal.ini""" 
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
             $sa=$using:saPWD
             $installaction="/ACTION=""Install"" /Q /IAcceptSqlServerLicenseTerms /SAPWD=$sa /configurationfile=""${SQLInstallationFolder}\ConfigurationFile_WithAllSettingsFinal.ini""" 
             }
             }
             Write-Log "Installing SQL Server After Reboot" -Color Green
             Start-Process -FilePath "setup.exe" -WorkingDirectory $InstallPath $installaction -Wait

            }
            elseif ($TotalInstanceServices.Count -ne 0)
            {
            Write-Log "SQL is installed on Previous step" -Color Green

            }


            }

            ###################Install SQL Server CU ####################
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
             
             Invoke-Command -Session $RunasDifferentUser -Script{
             #$backupfolder="D:\SQLData\2023_03_07_215318"
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
             #Check If SQL Server is Running or not
             $status =get-service $InstanceService.Name | select Status
             If($status.Status -eq "Running")
             {
             Write-Log "SQLServer is Running" -Color Green
             #Check If SQL Server is Clustered or not
             [array]$Clustered = Invoke-Sqlcmd -ServerInstance $SQLInstanceName -Query "select  SERVERPROPERTY('IsClustered') as IsClustered,SERVERPROPERTY('IsHadrEnabled') as IsHadrEnabled" -TrustServerCertificate  #-Credential $Cred
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
             Write-Log "Starting User DB Attachment"
             Import-CSV $userdbfilepath | ForEach-Object { 
             #Current row object
             $CSVRecord = $_
             $attachcmd2 = $CSVRecord.'TxtAttach'
             $dbname = $CSVRecord.'dbname'
             Write-Host $attachcmd2
             try
             {
             Write-Log "Database attachment starting for ${dbname}" -Color Green
             Invoke-sqlcmd -ServerInstance $SQLInstanceName -Query $attachcmd2 -QueryTimeout 3600 -TrustServerCertificate
             Write-Log "Database attachment completed for ${dbname}" -Color Green
             }
             Catch
             {
             Write-Log "Database attachment Failed for ${dbname}" -Color Red
             write-Host ($Error[0].Exception)
             Throw
             }
             }
            Write-Log "Starting System Databases recovery" -Color Green 
            $newsystemfiles=(Invoke-sqlcmd -ServerInstance $SQLInstanceName -TrustServerCertificate -Query "select filename from sysaltfiles where dbid in (1,3,4)").filename 
            Write-Log "Stopping SQL instance"
            Stop-Service  MSSQLSERVER
            foreach ($newsystemfile in $newsystemfiles){
            $newfilename=$newsystemfile+'_old'
            Rename-Item -Path $newsystemfile -NewName $newfilename
            $pathpos=$newsystemfile.LastIndexOf("\")
            $dbfilepos=($newsystemfile.length - $pathpos -1)
            $systempath=$newsystemfile.Substring(0,$pathpos+1)
            $dbfilename=$newsystemfile.SubString($newsystemfile.length - $dbfilepos) 
            $oldfile= (Get-ChildItem $using:backuplocation\ -Recurse -Include $dbfilename).name 
            Copy-Item -Path $using:backuplocation\$oldfile -Destination $systempath\

            }  
            Write-Log "System database files copied"
            Write-Log "Starting SQL Service"
            Start-Service  MSSQLSERVER
            }
