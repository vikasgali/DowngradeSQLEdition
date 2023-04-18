# DowngradeSQLEdition

Sample code to downgrade Standalone SQL Enterprise to other Editions(Standard,Developer,Web) .



# Pre-Requisites
1.Amazon EC2 windows Instance with SQL Server Enterprise Edition Installed
2.SQL Server Management Studio on SQL EC2 instance
3.S3 bucket for SQL Standard installation Media , Cumulative Update and Configuration
4.File to install SQL Server
5.EC2 instances to access S3 bucket to download the installation Media
6.System manager agent installed on EC2 instance

# High Level Steps
1.	Take Full backups of system and user databases of existing SQL Server Enterprise Edition
2.	Stop SQL Server Services
3.	Backup Copy master and msdb physical database files to Backup folder
4.	Uninstall Enterprise Edition software
5.	Install Standard/Developer edition
6.	Install Cumulative Update if provided in S3 location
7.	Attach SQL Server user databases from Enterprise Edition to Standard/Developer edition 
8.	Stop SQL Server Services
9.	Replace new master and msdb database files with the files we backup earlier. 
10.	Start SQL Server Services

