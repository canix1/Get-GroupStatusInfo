<#
.Synopsis
    Get-GroupStatusInfo.ps1
     
    AUTHOR: Robin Granberg (robin.g@home.se)
    
.DESCRIPTION
    List groups information like member count, when changed, when a member was changed etc.


.PARAMETER Path
 Where to start search, DistinguishedName within quotation mark (").

.PARAMETER NameFilter
 String filtering on group name.

.PARAMETER maxmembercount
 Set the maximum number of members (of any kind) in groups to retreive, Default 999999.
 Any value above 1499 will include all number of members.

.PARAMETER Server
 Name of Domain Controller.

.PARAMETER file
 Output file.

.PARAMETER ExcludeSecGroupMembers
 Exclude groups that contain other security groups.

.PARAMETER ExcludeComputerMembers
 Exclude groups that conatin computer objects.

.EXAMPLE
.\Get-GroupStatusInfo.ps1 -File C:\temp\groups.csv -NameFilter Big*

 List groups that starts with "Big" in the name

.EXAMPLE
 .\Get-GroupStatusInfo.ps1 -Path "dc=contoso,dc=com" -Server dc1 -File C:\Temp\Groups.csv 

 List all security groups that only contain users
 This command will search for security groups in the path and write the result in the file specified.

.EXAMPLE
.\Get-GroupStatusInfo.ps1 -Path "dc=contoso,dc=com" -Server dc1 -File C:\Temp\Groups.csv -maxmembercount 4

  This command will search for security groups with the maximum of 4 members, in the path and write the result in the file specified.

.EXAMPLE
.\Get-GroupStatusInfo.ps1 -Path "dc=contoso,dc=com" -Server dc1 -File C:\Temp\Groups.csv  -ExcludeSecGroupMembers

 List all security groups that only contain users
 This command will search for security groups that does not contain other security groups, in the path and write the result in the file specified.
 
.EXAMPLE
.\Get-GroupStatusInfo.ps1 -Path "dc=contoso,dc=com" -Server dc1 -File C:\Temp\Groups.csv  -ExcludeComputerMembers

 List all security groups that only contain users
 This command will search for security groups that does not contain computer objects, in the path and write the result in the file specified.


.OUTPUTS
    The output is an CSV,HTML or EXCEL report.

.LINK
    https://github.com/canix1

.NOTES
    Version: 0.12
   
#>

Param
(
    # DistinguishedName to start your search at. Always included as long as your filter matches your object.
    [Parameter(Mandatory = $false, 
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true, 
        ValueFromRemainingArguments = $false, 
        Position = 0,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String] 
    $File,
    [Parameter(Mandatory = $false, 
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true, 
        ValueFromRemainingArguments = $false, 
        Position = 0,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String] 
    $NameFilter,
    [Parameter(Mandatory = $false, 
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true, 
        ValueFromRemainingArguments = $false, 
        Position = 0,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $Server,
    [Parameter(Mandatory = $false, 
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true, 
        ValueFromRemainingArguments = $false, 
        Position = 0,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [int]
    $maxmembercount = 9999999,
    [Parameter(Mandatory = $false, 
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true, 
        ValueFromRemainingArguments = $false, 
        Position = 0,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [string]
    $Path,
    [Parameter(Mandatory = $false, 
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true, 
        ValueFromRemainingArguments = $false, 
        Position = 0,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $ExcludeSecGroupMembers,
    [Parameter(Mandatory = $false, 
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true, 
        ValueFromRemainingArguments = $false, 
        Position = 0,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $ExcludeComputerMembers,
    [Parameter(Mandatory = $false, 
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true, 
        ValueFromRemainingArguments = $false, 
        Position = 0,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $DistributionGroups
)

Begin
{
    $script:ErrCtrlrActionPreference = "SilentlyContinue"
    #==========================================================================
    # Function		: Write-CSV
    # Arguments     : Security Descriptor, OU distinguishedName, Ou put text file
    # Returns   	: n/a
    # Description   : Writes the object or collection to a text file in CSV format
    #==========================================================================
    function Write-CSV
    {
        Param($InputObject, $fileout, $order = "")
        $arrProperties = $InputObject[0] | Get-member -MemberType 'NoteProperty' | Select-Object -ExpandProperty 'Name'
        $strHeader = ""
        if ($order -ne "")
        {
            $arrProperties = $order
        }
        foreach ($Prop in $arrProperties)
        {
            if ($strHeader -eq "")
            {
                $strHeader = [char]34 + $Prop + [char]34
            }
            else
            {
                $strHeader = $strHeader + "," + [char]34 + $Prop + [char]34
            }
        }
        $strHeader | Out-File -Append -FilePath $fileout
        $InputObject | foreach {
        
            $strOutPut = ""
            foreach ($Prop in $arrProperties)
            {
                if ($strOutPut -eq "")
                {
                    $strOutPut = [char]34 + $($_.$Prop) + [char]34
                }
                else
                {
                    $strOutPut = $strOutPut + "," + [char]34 + $($_.$Prop) + [char]34
                }

            }
            $strOutPut | Out-File -Append -FilePath $fileout
        } 
    }
    #==========================================================================
    # Function	: GetNumberOfContributingSIDS
    # Arguments     : DN of AD object
    # Returns   	: int 
    # Description   : Return the number of contributing SID a security principal have in AD 
    #==========================================================================
    Function GetNumberOfContributingSIDS ($ADObjectPath)
    {

        $ADObject = [ADSI]"LDAP://$ADObjectPath"
        $ADObject.psbase.RefreshCache("tokenGroups")
        $SIDs = $ADObject.psbase.Properties.Item("tokenGroups")


        return $SIDs
    }
    #==========================================================================
    # Function	    : GetGroupLastMemberModDateAndVersion
    # Arguments     : Domain Controller, DN of AD object
    # Returns   	: Object with Date and Version
    # Description   : Return the last originating change and version from the objects value metadata 
    #==========================================================================
    Function GetGroupLastMemberModDateAndVersion()
    {
        Param($DomainController, $GroupDN)

        $metaList = New-Object System.Collections.ArrayList
        $metaList.Clear()
        $Group = [ADSI]"LDAP://$DomainController/$GroupDN"

        $Group.psbase.RefreshCache("msds-replvaluemetadata")


        & { #Try
            $global:objMetaData = $Group.psbase.Properties.Item("msds-replvaluemetadata") #.tostring().replace("&","")
        }
        Trap [SystemException]
        {
            write-host ("$GroupDN `n TRAP: " + $_)
        }
        $global:objMetaData = $global:objMetaData.tostring().replace("&", "")
        $global:objMetaData = "<Node>" + $global:objMetaData
        $global:objMetaData | out-file -filepath ".\MMMM.txt" 
        $global:objMetaData = $global:objMetaData + "</Node>"
   
        [xml]$xmlfile = $global:objMetaData
        foreach ($payload in $xmlfile.Node.DS_REPL_VALUE_META_DATA)
        {

            [void] $metaList.add($payload.ftimeLastOriginatingChange)

        }



        If ($metalist -eq "")
        {
            $MetaDataObject = $null
        }
        else
        {
            $GroupMemberDate = $($metaList | Sort-Object | select -last 1)
            if ($GroupMemberDate)
            {
                $date = $(get-date $GroupMemberDate -UFormat "%Y-%m-%d %H:%M:%S")
                $version = $payload.dwVersion
            }
            else
            {
                $date = "N/A"
                $version = "N/A"
            }
            $MetaDataObject = [pscustomobject][ordered]@{
                date        = $date ; `
                    version = $version

            }
        }

        return $MetaDataObject
    }
    #==========================================================================
    # Function	    : EnumLargeGroup
    # Arguments     : Domain Controller, DN of AD object
    # Returns   	: Int
    # Description   : Return number of members in a group
    #==========================================================================
    Function EnumLargeGroup
    {
        Param ($DC, $GroupDN)


        # Use ADO to search entire domain.
        #$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $Root = New-Object System.DirectoryServices.DirectoryEntry("GC://$DC/$GroupDN")
        #$Root = $Domain.GetDirectoryEntry()

        $GroupShortName = $Root.psbase.Properties.Item("samAccountName")

        $adoConnection = New-Object -comObject "ADODB.Connection"
        $adoCommand = New-Object -comObject "ADODB.Command"
        $adoConnection.Open("Provider=ADsDSOObject;")
        $adoCommand.ActiveConnection = $adoConnection
        $adoCommand.Properties.Item("Page Size") = 200
        $adoCommand.Properties.Item("Timeout") = 30
        $adoCommand.Properties.Item("Cache Results") = $False

        $Base = $Root.distinguishedName
        $Scope = "base"
        $Filter = "(&(objectCategory=group)(sAMAccountName=$GroupShortName))"

        # Setup range limits.
        $Last = $False
        $RangeStep = 1499
        $LowRange = 0
        $HighRange = $LowRange + $RangeStep
        $Total = 0
        $ExitFlag = $False

        Do
        {
            If ($Last -eq $True)
            {
                # Retrieve remaining members (less than 1000).
                $Attributes = "member;range=$LowRange-*"
            }
            Else
            {
                # Retrieve 1000 members.
                $Attributes = "member;range=$LowRange-$HighRange"
            }
            $Query = "<GC://$DC/$Base>;$Filter;$Attributes;$Scope"

            $adoCommand.CommandText = $Query
            $adoRecordset = $adoCommand.Execute()
            $Count = 0

            $Members = $adoRecordset.Fields.Item("$Attributes").Value
            If ($Members -eq $Null)
            {
                "Group $Group not found"
                $Last = $True
            }
            Else
            {
                # If $Members is not an array, no members were retrieved.
                If ($Members.GetType().Name -eq "Object[]")
                {
                    ForEach ($Member In $Members)
                    {

                        $objMember = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($Member)")

                        $sttObjectClass = ""
                        $sttObjectClass = $($objMember.psbase.Properties.Item("objectClass"))[$($objMember.psbase.Properties.Item("objectClass")).count - 1]
  
                        if (!($sttObjectClass -eq ""))
                        {
                            if (($($objMember.psbase.Properties.Item("groupType")) -eq "8") -or ($($objMember.psbase.Properties.Item("groupType")) -eq "4") -or ($($objMember.psbase.Properties.Item("groupType")) -eq "2"))
                            {

				
					
                            }
                            else
                            {
                                $global:bolOnlyDistGrpMember = $false
                            }   

                            if ($ExcludeComputerMembers -eq $true)
                            {
                                if ($sttObjectClass -eq "computer")
                                {


                                    $global:FailOnCriteria = $true
                                    break


                                }
                            }
                            if ($ExcludeSecGroupMembers -eq $true)
                            {
                                if ($sttObjectClass -eq "group")
                                {

                                    if (($($objMember.psbase.Properties.Item("groupType")) -eq "-2147483640") -or ($($objMember.psbase.Properties.Item("groupType")) -eq "-2147483646") -or ($($objMember.psbase.Properties.Item("groupType")) -eq "-2147483644"))
                                    {

                                        $global:FailOnCriteria = $true
                                        break
					
                                    }

                                }
                            }

                        }
                        $Count = $Count + 1
                    }
                }
            }
            $adoRecordset.Close()
            if ($global:FailOnCriteria -eq $true)
            {
                $Total = -1
                $Last = $True
            }
            else
            {
                $Total = $Total + $Count
            }
            # If this is the last query, exit the Do loop.
            If ($Last -eq $True) { $ExitFlag = $True }
            Else
            {
                # If the previous query returned no members, the query failed.
                # Perform one more query to retrieve remaining members (less than 1000).
                If ($Count -eq 0) { $Last = $True }
                Else
                {
                    # Retrieve the next 1000 members.
                    $LowRange = $HighRange + 1
                    $HighRange = $LowRange + $RangeStep
                }
            }
        } Until ($ExitFlag -eq $True)

        $adoConnection.Close()
        return $Total
    }

}
Process
{
    $GroupOutPut = New-Object System.Collections.ArrayList

    $null = add-type -AssemblyName System.DirectoryServices.Protocols
    $Domain = ""
    $colTotal = 0
    
    $FileOK = $true

    #Test file location
    if (!($file -eq ""))
    {

        if (Test-Path $file)
        {
            Remove-Item $file
        }
        else
        {
            try
            {
                $rslt = New-Item -ItemType File -Path $File -ErrorAction Stop
                $rslt = $null
            }
            catch
            {
                $FileOK = $false
            }
        }
    }
    if ($FileOK)
    {
        ## Get Domain Name
        $LDAPConnection = $null
        $request = $null
        $response = $null
        $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($Domain)
        $LDAPConnection.SessionOptions.ReferralChasing = "None"
        $request = New-Object System.directoryServices.Protocols.SearchRequest($null, "(objectClass=*)", "base")
        [void]$request.Attributes.Add("defaultnamingcontext")
        [void]$request.Attributes.Add("configurationNamingContext")
        [void]$request.Attributes.Add("dnshostname")

        try
        {
            $response = $LDAPConnection.SendRequest($request)
            $DomainDN = $response.Entries[0].attributes.defaultnamingcontext[0]
            $ConfigDN = $response.Entries[0].attributes.configurationnamingcontext[0]
            $strDC = $response.Entries[0].Attributes.dnshostname[0]
            $bolLDAPConnection = $true
        }
        catch
        {
            $bolLDAPConnection = $false
            Write-Error "Failed! Domain does not exist or can not be connected"
            break;
        }

        if ($bolLDAPConnection)
        {

            if ($Path -eq "")
            {
                $Path = $DomainDN
            }

            if ($Server -eq "")
            {
                $Server = $strDC
            }

            if ($NameFilter)
            {

                if ($DistributionGroups)
                {
                    $strFilter = "(&(objectCategory=Group)(name=" + $NameFilter + ")(|(groupType=2)(groupType=4)(groupType=8)))"
                } 
                else
                {
                    $strFilter = "(&(objectCategory=Group)(name=" + $NameFilter + ")(|(groupType=-2147483640)(groupType=-2147483644)(groupType=-2147483646)))"
                }
            }
            else
            {

                if ($DistributionGroups)
                {
                    $strFilter = "(&(objectCategory=Group)(|(groupType=2)(groupType=4)(groupType=8)))"
                } 
                else
                {
                    $strFilter = "(&(objectCategory=Group)(|(groupType=-2147483640)(groupType=-2147483644)(groupType=-2147483646)))"
                }
            }

    

            $i = 0
            $PageSize = 1000
            $TimeoutSeconds = 500
        
            #First Query will count the objects
            $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($Server)
            $LDAPConnection.SessionOptions.ReferralChasing = "None"
            $request = New-Object System.directoryServices.Protocols.SearchRequest($Path, $strFilter, "Subtree")
            [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($pageSize)
            [void]$request.Attributes.Add("samaccountname")

            $request.Controls.Add($pagedRqc) | Out-Null

            while ($true)
            {
                $response = $LdapConnection.SendRequest($request, (new-object System.Timespan(0, 0, $TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];
                
                #for paged search, the response for paged search result control - we will need a cookie from result later
                if ($pageSize -gt 0)
                {
                    [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $null;
                    if ($response.Controls.Length -gt 0)
                    {
                        foreach ($ctrl in $response.Controls)
                        {
                            if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl])
                            {
                                $prrc = $ctrl;
                                break;
                            }
                        }
                    }
                    if ($null -eq $prrc)
                    {
                        #server was unable to process paged search
                        throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
                    }
                }
                #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
                $colTotal = $colTotal + $response.Entries.count


                if ($pageSize -gt 0)
                {
                    if ($prrc.Cookie.Length -eq 0)
                    {
                        #last page --> we're done
                        break;
                    }
                    #pass the search cookie back to server in next paged request
                    $pagedRqc.Cookie = $prrc.Cookie;
                }
                else
                {
                    #exit the processing for non-paged search
                    break;
                }
            }#End While

            if ($colTotal -gt 0)
            {
                $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($Server)
                $LDAPConnection.SessionOptions.ReferralChasing = "None"
                $request = New-Object System.directoryServices.Protocols.SearchRequest($Path, $strFilter, "Subtree")
                [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($pageSize)
                [void]$request.Attributes.Add("samaccountname")
                [void]$request.Attributes.Add("grouptype")
                [void]$request.Attributes.Add("member")
                [void]$request.Attributes.Add("description")
                [void]$request.Attributes.Add("objectguid")
                [void]$request.Attributes.Add("whencreated")
                [void]$request.Attributes.Add("whenchanged")


                $request.Controls.Add($pagedRqc) | Out-Null


                while ($true)
                {
                    $response = $LdapConnection.SendRequest($request, (new-object System.Timespan(0, 0, $TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];
                
                    #for paged search, the response for paged search result control - we will need a cookie from result later
                    if ($pageSize -gt 0)
                    {
                        [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $null;
                        if ($response.Controls.Length -gt 0)
                        {
                            foreach ($ctrl in $response.Controls)
                            {
                                if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl])
                                {
                                    $prrc = $ctrl;
                                    break;
                                }
                            }
                        }
                        if ($null -eq $prrc)
                        {
                            #server was unable to process paged search
                            throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
                        }
                    }
                    #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
                    $colResults = $response.Entries

                    foreach ($objResult in $colResults)
                    {

                        $i++
                        [int]$pct = ($i / $colTotal) * 100
                        Write-Progress -Activity "Collecting group objects" -Status "Currently scanning $i of $colTotal objects" -Id 0 -CurrentOperation $objResult.Attributes.samaccountname[0] -PercentComplete $pct 

                        $bolLargeGroup = $false
                        $global:bolOnlyDistGrpMember = $true

                        $GrpPath = $objResult.distinguishedName

                        $bolMemberOfOtherSecgrp = $false
                        if ($GroupNestedSID)
                        {
                            $intNestedSIDs = $GroupNestedSID.Count
                            ForEach ($Value In $GroupNestedSID)
                            {
                                $SID = New-Object System.Security.Principal.SecurityIdentifier $Value, 0


                                $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($Server)
                                $LDAPConnection.SessionOptions.ReferralChasing = "None"
                                $request = New-Object System.directoryServices.Protocols.SearchRequest
                                if ($global:bolShowDeleted)
                                {
                                    [string] $LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
                                    [void]$request.Controls.Add((New-Object "System.DirectoryServices.Protocols.DirectoryControl" -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
                                }
                                $request.DistinguishedName = "<SID=$($SID.Value.tostring())>"
                                $request.Filter = "(name=*)"
                                $request.Scope = "Base"
                                [void]$request.Attributes.Add("grouptype")
                                $response = $LDAPConnection.SendRequest($request)
                                $result = $response.Entries[0]

                                $groupType = $result.attributes.grouptype[0]
                                if (($groupType -eq "-2147483640") -or ($groupType -eq "-2147483646") -or ($groupType -eq "-2147483644"))
                                {
                                    $bolMemberOfOtherSecgrp = $true
                                }

    
                            }
                        }
                        else
                        {
                            $intNestedSIDs = 0
                        }
                        $groupname = $objResult.distinguishedname.tostring()	
                        $groupname = $groupname.Replace("/", "\/")

                        $global:FailOnCriteria = $false
                        $members = $objResult.attributes.member.count
                        if ($members -le $maxmembercount)
                        {
                    
                            #Check if the group has a large amount of members (More than 1499)
                            if ( $objResult.Attributes.'member;range=0-1499')
                            {

                                $members = EnumLargeGroup $server $groupname
                                If ($global:FailOnCriteria -eq $false)
                                {
                                    $GroupMetadata = GetGroupLastMemberModDateAndVersion $Server $groupname
                                    $LastMemberModDate = $GroupMetadata.date
                                    $MemberVersion = $GroupMetadata.version
                                }
                                If ($global:FailOnCriteria -eq $false)
                                {


                                    $DistOnly = "false"
                                    if ($global:bolOnlyDistGrpMember -eq $true)
                                    {
                                        $DistOnly = "true"
                                    }

                                    if ($objResult.Attributes.description)
                                    {
                                        $Description = $objResult.Attributes.description[0]
                                    }
                                    else
                                    {
                                        $Description = ""
                                    }

                                    $objPSCustom_Group = [pscustomobject][ordered]@{
                                        GUID                                   = $(([System.GUID]$objResult.Attributes.objectguid[0]).Guid.tostring()); `
                                            samAccountName                     = $objResult.Attributes.samaccountname[0]; `
                                            DN                                 = $groupname; `
                                            Description                        = $Description; `
                                            'When Created'                     = $(get-date ([DateTime]::ParseExact($objResult.Attributes.whencreated[-1], "yyyyMMddHHmmss.0Z", $null, "AssumeUniversal, AdjustToUniversal"))-UFormat "%Y-%m-%d %H:%M:%S"); `
                                            'When Modified'                    = $(get-date ([DateTime]::ParseExact($objResult.Attributes.whenchanged[-1], "yyyyMMddHHmmss.0Z", $null, "AssumeUniversal, AdjustToUniversal"))-UFormat "%Y-%m-%d %H:%M:%S"); `
                                            'Last Member Modfied'              = $LastMemberModDate; `
                                            'Member version'                   = $MemberVersion; `
                                            'Nested SIDs'                      = $intNestedSIDs; `
                                            'Member of Security Group'         = $bolMemberOfOtherSecgrp; `
                                            'Member Count'                     = $members; `
                                            'Members Only Distribution Groups' = $DistOnly
                                    }
        
                                    Switch ($objResult.Attributes.grouptype[0])
                                    {
                                        "8"
                                        { $GroupType = "Distribution Group - Domain Local" }
                                        "4"
                                        { $GroupType = "Distribution Group - Global" }
                                        "2"
                                        { $GroupType = "Distribution Group - Global" }
                                        "-2147483640"
                                        { $GroupType = "Security Group - Universal" }
                                        "-2147483646"
                                        { $GroupType = "Security Group - Global" }
                                        "-2147483644"
                                        { $GroupType = "Security Group - Domain Local" }
                                        default
                                        { $GroupType = "Security Group - Domain Local" }
                                    }

                                    Add-Member -InputObject  $objPSCustom_Group -MemberType NoteProperty -Name "Group Type" -Value $GroupType
                                    [VOID]$GroupOutPut.Add($objPSCustom_Group)

                                }
                            }
                            else
                            {
                                if ($members -gt 0)
                                {
                                    foreach ($user in @($objResult.Attributes.member[0..$members]))
                                    {

                                        $objMember = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($user)")
                                        $sttObjectClass = ""
                                        $sttObjectClass = $($objMember.psbase.Properties.Item("objectClass"))[$($objMember.psbase.Properties.Item("objectClass")).count - 1]
                                        if (!($sttObjectClass -eq ""))
                                        {
            

                                            if (($($objMember.psbase.Properties.Item("groupType")) -eq "8") -or ($($objMember.psbase.Properties.Item("groupType")) -eq "4") -or ($($objMember.psbase.Properties.Item("groupType")) -eq "2"))
                                            {

				
					
                                            }
                                            else
                                            {

                                                $global:bolOnlyDistGrpMember = $false

                                            }            
            
                                            if ($ExcludeComputerMembers -eq $true)
                                            {
                                                if ($sttObjectClass -eq "computer")
                                                {


                                                    $global:FailOnCriteria = $true
                                                    break


                                                }
                                            }
                                            if ($ExcludeSecGroupMembers -eq $true)
                                            {
                                                if ($sttObjectClass -eq "group")
                                                {

                                                    if (($($objMember.psbase.Properties.Item("groupType")) -eq "-2147483640") -or ($($objMember.psbase.Properties.Item("groupType")) -eq "-2147483646") -or ($($objMember.psbase.Properties.Item("groupType")) -eq "-2147483644"))
                                                    {

                                                        $global:FailOnCriteria = $true
                                                        break
					
                                                    }

                                                }
                                            }

                                        }



                                    }

                                    If ($global:FailOnCriteria -eq $false)
                                    {
                                        $GroupMetadata = GetGroupLastMemberModDateAndVersion $Server $groupname
                                        $LastMemberModDate = $GroupMetadata.date
                                        $MemberVersion = $GroupMetadata.version
                                    }
                                }
                                else
                                {
                                    $members = 0
                                    $GroupMetadata = GetGroupLastMemberModDateAndVersion $Server $groupname
                                    $LastMemberModDate = $GroupMetadata.date
                                    $MemberVersion = $GroupMetadata.version
                                }
                                If ($global:FailOnCriteria -eq $false)
                                {
                                    $DistOnly = "false"
                                    if ($members -gt 0)
                                    {
                                        if ($global:bolOnlyDistGrpMember -eq $true)
                                        {
                                            $DistOnly = "true"
                                        }
                                    }
                                    else
                                    {
                                        $DistOnly = "N/A"
                                    }

                                    if ($objResult.Attributes.description)
                                    {
                                        $Description = $objResult.Attributes.description[0]
                                    }
                                    else
                                    {
                                        $Description = ""
                                    }

                                    $objPSCustom_Group = [pscustomobject][ordered]@{
                                        GUID                                   = $(([System.GUID]$objResult.Attributes.objectguid[0]).Guid.tostring()); `
                                            samAccountName                     = $objResult.Attributes.samaccountname[0]; `
                                            DN                                 = $groupname; `
                                            Description                        = $Description; `
                                            'When Created'                     = $(get-date ([DateTime]::ParseExact($objResult.Attributes.whencreated[-1], "yyyyMMddHHmmss.0Z", $null, "AssumeUniversal, AdjustToUniversal"))-UFormat "%Y-%m-%d %H:%M:%S"); `
                                            'When Modified'                    = $(get-date ([DateTime]::ParseExact($objResult.Attributes.whenchanged[-1], "yyyyMMddHHmmss.0Z", $null, "AssumeUniversal, AdjustToUniversal"))-UFormat "%Y-%m-%d %H:%M:%S"); `
                                            'Last Member Modfied'              = $LastMemberModDate; `
                                            'Member version'                   = $MemberVersion; `
                                            'Nested SIDs'                      = $intNestedSIDs; `
                                            'Member of Security Group'         = $bolMemberOfOtherSecgrp; `
                                            'Member Count'                     = $members; `
                                            'Members Only Distribution Groups' = $DistOnly
                                    }

                                    Switch ($objResult.Attributes.grouptype[0])
                                    {
                                        "8"
                                        { $GroupType = "Distribution Group - Domain Local" }
                                        "4"
                                        { $GroupType = "Distribution Group - Global" }
                                        "2"
                                        { $GroupType = "Distribution Group - Global" }
                                        "-2147483640"
                                        { $GroupType = "Security Group - Universal" }
                                        "-2147483646"
                                        { $GroupType = "Security Group - Global" }
                                        "-2147483644"
                                        { $GroupType = "Security Group - Domain Local" }
                                        default
                                        { $GroupType = "Security Group - Domain Local" }
                                    }

                                    Add-Member -InputObject  $objPSCustom_Group -MemberType NoteProperty -Name "Group Type" -Value $GroupType

                                    [VOID]$GroupOutPut.Add($objPSCustom_Group)
                                }
                            }
                        }#End If $members -le $maxmembercount

                    }
                    if ($pageSize -gt 0)
                    {
                        if ($prrc.Cookie.Length -eq 0)
                        {
                            #last page --> we're done
                            break;
                        }
                        #pass the search cookie back to server in next paged request
                        $pagedRqc.Cookie = $prrc.Cookie;
                    }
                    else
                    {
                        #exit the processing for non-paged search
                        break;
                    }
                }#End While
            }
            else
            {
                Write-Warning "No groups found!"
            }


            if ($GroupOutPut)
            {
                if ($File)
                {
                    Write-CSV $GroupOutPut $file 
                    Write-Output "Groups saved in: $file "
                }
                else
                {
                    $GroupOutPut
                }


            }
        }
    }
    else
    {
        Write-Error "`n================================================================   `n    `nProblem with the file path: $file`n     `n================================================================`n   "
    }
}
End
{

}