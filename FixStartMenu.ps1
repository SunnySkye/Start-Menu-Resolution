Import-Module ActiveDirectory

$FullName = Read-Host -Prompt "Enter name [LAST, FIRST]"
  
$SamAccountInfo = Get-ADUser -Filter "Name -Like '$FullName*'" | Select-Object Name, SID, SamAccountName
$UserSID = $SamAccountInfo.SID
$ComputerName = Read-Host -Prompt "Please enter computer hostname"
Write-Host ("ComputerName: " + $ComputerName)
$Answer = Read-Host -Prompt "Continue [Y/N]?"
if ($Answer.ToLower() = 'y') {
    if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -Buffer 8) {
        Write-Host ("Connecting to " + $ComputerName)
        $Session = New-PSSession -ComputerName $ComputerName
            Invoke-Command -Session $Session -ScriptBlock {
            Param ($Sid, $ComputerName, $EUUserName)
            Write-Host ("Sid: ", $Sid)
            Write-Host ("Fixing permissions on \HKEY_USERS\" + $Sid + "\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
            $Acl = Get-Acl -Path ("Registry::\HKEY_USERS\" + $Sid + "\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
            $idRef = [System.Security.Principal.NTAccount]::New("ALL APPLICATION PACKAGES")
            $regRights = [System.Security.AccessControl.RegistryRights]::ReadKey
            $inhFlags = [System.Security.AccessControl.InheritanceFlags]'3'
            $prFlags = [System.Security.AccessControl.PropagationFlags]::None
            $acType = [System.Security.AccessControl.AccessControlType]::Allow
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($idRef, $regRights, $inhFlags, $prFlags, $acType)
            $acl.AddAccessRule($rule)
            $acl | Set-Acl -Path ("Registry::\HKEY_USERS\" + $Sid + "\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
 
            $AadPath = ("C:\Users\" + $EUUserName + "\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy")
            Write-Host ("Deleting " + $AadPath)
            Remove-Item $AadPath -Recurse -Force
           
            # Add registry key to RunOnce
            $RegPath = ("Registry::\HKEY_USERS\" + $Sid + "\Software\Microsoft\Windows\CurrentVersion\RunOnce")
            New-Item -Path $RegPath -Force
            New-ItemProperty -Path $RegPath -Name "FixStartMenu" -Value "C:\Temp\FixStartMenuOnce.bat" -PropertyType String

            Write-Host ("Deleting " + $ComputerName + " registry key: " + $Sid + "\SOFTWARE\Microsoft\Office\16.0\Common\Identity")
            $RegDeleteAnswer = Read-Host -Prompt "Continue [Y/N]?"
            if ($RegDeleteAnswer.ToLower() = 'y') 
            {
                $OfficeRegPath = ("Registry::\HKEY_USERS\" + $Sid + "\SOFTWARE\Microsoft\Office\16.0\Common\Identity")
                Remove-Item -Path $OfficeRegPath -Recurse
            }

        } -ArgumentList $SamAccountInfo.Sid, $ComputerName, $SamAccountInfo.SamAccountName
        $Session | Remove-PSSession
       
        Write-Host ("Copying C:\Temp\FixStartMenuOnce.bat to \\" + $ComputerName + "\C$\Temp")
        Copy-Item C:\Temp\FixStartMenuOnce.bat -Destination ("\\" + $ComputerName + "\C$\Temp")

# User should be able to reboot at this point and their problem solved.
        }
    } else {
        Write-Host "PC is offline!"
    }
