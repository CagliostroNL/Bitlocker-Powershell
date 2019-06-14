#Requires -RunAsAdministrator
    function add_registry() {
    
    Write-Host "[+] Registry keys toevoegen"
    #Registry keys toevoegen
    reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseAdvancedStartup /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UsePIN /t REG_DWORD /d 2 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMPIN /t REG_DWORD /d 2 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPM /t REG_DWORD /d 2 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMKey /t REG_DWORD /d 2 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMKeyPIN /t REG_DWORD /d 2 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseEnhancedPin /t REG_DWORD /d 1 /f
    }
    function recovery_file(){ 

    $usb_drives = Get-CimInstance -Class Win32_DiskDrive -Filter 'InterfaceType = "USB"' -KeyOnly | 
        Get-CimAssociatedInstance -ResultClassName Win32_DiskPartition -KeyOnly |
        Get-CimAssociatedInstance -ResultClassName Win32_LogicalDisk  
    $usb_path = $usb_drives | Select-Object -Expand deviceid -First 1
    $driveletter = $usb_path + "\"
    $hostname = hostname

    if($usb_path -ne $null)
    {
         Write-Host  "The next USB will be selected"
         $driveletter
         
         $recovery_file = $driveletter + "Recoverykey-" + $hostname + ".txt"
         (Get-BitLockerVolume).KeyProtector.RecoveryPassword > $recovery_file

        }
    elseif(!$usb_path) 
        {
        $recovery_file = "C:\" + "RecoveryKey-" + $hostname + ".txt"
        Write-Host "Didn't found any USB Drives.`nThe Recovery file will be writen to" $recovery_file
        Write-Host "This is not advised, make sure to back up the file somewere else, and delete the file."
        (Get-BitLockerVolume).KeyProtector.RecoveryPassword > $recovery_file
        
        
    }
    
}
    function encrypt_c(){ 
    # Prompt user until passwords are the same
    Do
                            {
        $PromptUser = Read-Host -Prompt "Write your desired pincode"
        $PromptUser1 = Read-Host -Prompt "Write your desired pincode again"
        if ($PromptUser -ne $PromptUser1)
         { 
            Write-Host "Pincodes don't match"
        }
            }
     While ($PromptUser -ne $PromptUser1) 

        
        if($PromptUser-eq $PromptUser1)
        {
              #Plaintext to secure text
              $SecureString = ConvertTo-SecureString $PromptUser -AsPlainText -Force
              #Encrypt station C:
              Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -Pin $SecureString -TpmAndPinProtector -SkipHardwareTest
              #Recovery key 
              Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
      
              #Select usb drive and write recovery file to usb
              recovery_file
     
      }

    }  



Write-Host "Make sure ONLY ONE USB is connected. Recovery file will be writen to the USB drive!"
$get_userinput = Read-Host("Is their a USB connected Yes/No")


if($get_userinput -eq "yes" -or $get_userinput -eq "y")
{ 

    add_registry
    encrypt_c
}
elseif ($get_userinput -eq "no" -or $get_userinput -eq "n")
{
    Write-Host "Bye!!"
    timeout(2)
    exit
}
