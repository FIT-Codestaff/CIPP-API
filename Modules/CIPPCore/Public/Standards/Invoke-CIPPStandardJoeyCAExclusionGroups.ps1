function Invoke-CIPPStandardJoeyCAExclusionGroups {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) JoeyCAExclusionGroups
    .SYNOPSIS
        (Label) Create Joey CA Baseline Exclusion Groups
    .DESCRIPTION
        (Helptext) Creates all required exclusion groups for Joey Verlinden's Conditional Access Baseline framework (j0eyv/ConditionalAccessBaseline on GitHub). This standard MUST be applied BEFORE deploying CA policy templates.
    .NOTES
        CAT
            Entra (AAD) Standards
        TAG
            "mediumimpact"
        ADDEDCOMPONENT
            {"type":"input","name":"standards.JoeyCAExclusionGroups.BreakGlassUPN","label":"Break Glass Account UPN (optional)"}
        IMPACT
            Medium Impact
        POWERSHELLEQUIVALENT
            New-MgGroup
        RECOMMENDEDBY
            "MSP Community"
        UPDATECOMMENTBLOCK
            Run On Update
    .EXAMPLE
        Invoke-CIPPStandardJoeyCAExclusionGroups -Tenant "contoso.onmicrosoft.com" -Settings @{BreakGlassUPN="breakglass@contoso.com"}
    #>

    param($Tenant, $Settings)
    
    $CurrentInfo = New-GraphGetRequest -Uri 'https://graph.microsoft.com/v1.0/groups?$select=displayName,id' -tenantid $Tenant
    
    # Define all required exclusion groups from Joey's baseline
    $exclusionGroups = @(
        # Break Glass / Emergency Access
        @{
            Name        = "CA-BreakGlassAccounts - Exclude"
            Description = "Break glass/emergency access accounts excluded from all CA policies"
        },
        
        # Global Policies (CA001-CA006)
        @{
            Name        = "CA001-Global-AttackSurfaceReduction-AnyApp-AnyPlatform-BLOCK-CountryWhitelist - Exclude"
            Description = "Exclusions for country whitelist blocking policy"
        },
        @{
            Name        = "CA002-Global-IdentityProtection-AnyApp-AnyPlatform-Block-LegacyAuthentication - Exclude"
            Description = "Exclusions for legacy authentication blocking (service accounts only)"
        },
        @{
            Name        = "CA003-Global-BaseProtection-RegisterOrJoin-AnyPlatform-MFA - Exclude"
            Description = "Exclusions for device registration/join MFA requirement"
        },
        @{
            Name        = "CA004-Global-IdentityProtection-AnyApp-AnyPlatform-AuthenticationFlows - Exclude"
            Description = "Exclusions for authentication flows policy"
        },
        @{
            Name        = "CA005-Global-DataProtection-Office365-AnyPlatform-Unmanaged-AppEnforcedRestrictions-BlockDownload - Exclude"
            Description = "Exclusions for unmanaged device download blocking"
        },
        @{
            Name        = "CA006-Global-DataProtection-Office365-iOSenAndroid-RequireAppProtection - Exclude"
            Description = "Exclusions for mobile app protection requirement"
        },
        
        # Admin Policies (CA100-CA105)
        @{
            Name        = "CA100-Admins-IdentityProtection-AdminPortals-AnyPlatform-MFA - Exclude"
            Description = "Exclusions for admin portal MFA requirement"
        },
        @{
            Name        = "CA101-Admins-IdentityProtection-AnyApp-AnyPlatform-MFA - Exclude"
            Description = "Exclusions for admin MFA on all apps"
        },
        @{
            Name        = "CA102-Admins-IdentityProtection-AllApps-AnyPlatform-SigninFrequency - Exclude"
            Description = "Exclusions for admin sign-in frequency controls"
        },
        @{
            Name        = "CA103-Admins-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser - Exclude"
            Description = "Exclusions for admin persistent browser session blocking"
        },
        @{
            Name        = "CA104-Admins-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation - Exclude"
            Description = "Exclusions for admin continuous access evaluation"
        },
        @{
            Name        = "CA105-Admins-IdentityProtection-AnyApp-AnyPlatform-PhishingResistantMFA - Exclude"
            Description = "Exclusions for phishing-resistant MFA requirement"
        },
        
        # Internal User Policies (CA200-CA210)
        @{
            Name        = "CA200-Internals-IdentityProtection-AnyApp-AnyPlatform-MFA - Exclude"
            Description = "Exclusions for internal user MFA requirement"
        },
        @{
            Name        = "CA201-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRisk - Exclude"
            Description = "Exclusions for high-risk sign-in blocking"
        },
        @{
            Name        = "CA202-Internals-IdentityProtection-AllApps-WindowsMacOS-SigninFrequency-UnmanagedDevices - Exclude"
            Description = "Exclusions for unmanaged device sign-in frequency"
        },
        @{
            Name        = "CA203-Internals-AppProtection-MicrosoftIntuneEnrollment-AnyPlatform-MFA - Exclude"
            Description = "Exclusions for Intune enrollment MFA"
        },
        @{
            Name        = "CA204-Internals-DataProtection-AllApps-WindowsMacOS-CompliantorAADHJ - Exclude"
            Description = "Exclusions for compliant/hybrid joined device requirement"
        },
        @{
            Name        = "CA205-Internals-DataProtection-Office365-WindowsMacOS-Unmanaged-PersistentBrowser - Exclude"
            Description = "Exclusions for persistent browser blocking on unmanaged devices"
        },
        @{
            Name        = "CA206-Internals-AppProtection-Office365-iOSAndroid-ClientAppORCompliant - Exclude"
            Description = "Exclusions for mobile client app or compliance requirement"
        },
        @{
            Name        = "CA207-Internals-DataProtection-Office365-AllPlatforms-BlockSpecificApps - Exclude"
            Description = "Exclusions for blocking specific apps"
        },
        @{
            Name        = "CA208-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-MediumRisk - Exclude"
            Description = "Exclusions for medium-risk user blocking"
        },
        @{
            Name        = "CA209-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-LowRisk - Exclude"
            Description = "Exclusions for low-risk sign-in MFA requirement"
        },
        @{
            Name        = "CA210-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskUser - Exclude"
            Description = "Exclusions for high-risk user blocking"
        },
        
        # Guest Policies (CA300-CA304)
        @{
            Name        = "CA300-Guests-IdentityProtection-AnyApp-AnyPlatform-MFA - Exclude"
            Description = "Exclusions for guest MFA requirement"
        },
        @{
            Name        = "CA301-Guests-AttackSurfaceReduction-AnyApp-AnyPlatform-BlockNonAADAppAccess - Exclude"
            Description = "Exclusions for guest non-AAD app blocking"
        },
        @{
            Name        = "CA302-Guests-DataProtection-Office365-AllPlatforms-BLOCK-Copy-Download - Exclude"
            Description = "Exclusions for guest download/copy restrictions"
        },
        @{
            Name        = "CA303-Guests-DataProtection-Office365-AllPlatforms-BlockSpecificApps - Exclude"
            Description = "Exclusions for guest app blocking"
        },
        @{
            Name        = "CA304-Guests-IdentityProtection-AllApps-AllPlatforms-SigninFrequency - Exclude"
            Description = "Exclusions for guest sign-in frequency"
        },
        
        # Guest Admin Policies (CA400-CA403)
        @{
            Name        = "CA400-GuestAdmins-IdentityProtection-AnyApp-AnyPlatform-MFA - Exclude"
            Description = "Exclusions for guest admin MFA requirement"
        },
        @{
            Name        = "CA401-GuestAdmins-AttackSurfaceReduction-AnyApp-AnyPlatform-BlockNonAADAppAccess - Exclude"
            Description = "Exclusions for guest admin non-AAD app blocking"
        },
        @{
            Name        = "CA402-GuestAdmins-DataProtection-Office365-AllPlatforms-BLOCK-Copy-Download - Exclude"
            Description = "Exclusions for guest admin download/copy restrictions"
        },
        @{
            Name        = "CA403-GuestAdmins-IdentityProtection-AllApps-AllPlatforms-SigninFrequency - Exclude"
            Description = "Exclusions for guest admin sign-in frequency"
        },
        
        # Developer Policies (CA500-CA501)
        @{
            Name        = "CA500-Developers-AttackSurfaceReduction-VisualStudio-AllPlatforms-MFA - Exclude"
            Description = "Exclusions for Visual Studio MFA requirement"
        },
        @{
            Name        = "CA501-Developers-AttackSurfaceReduction-Azure-AllPlatforms-MFA - Exclude"
            Description = "Exclusions for Azure DevOps MFA requirement"
        },
        
        # Additional Support Groups
        @{
            Name        = "CA-ServiceAccounts - Exclude"
            Description = "Service accounts that need CA policy exclusions (review regularly)"
        },
        @{
            Name        = "CA-TemporaryExclusions - Exclude"
            Description = "Temporary exclusions for troubleshooting (should be empty in production)"
        }
    )

    If ($Settings.remediate -eq $true) {
        Write-LogMessage -API 'Standards' -tenant $tenant -message 'Joey CA Baseline exclusion groups will be created.' -sev Info
        
        $CreatedGroups = 0
        $ExistingGroups = 0
        $ErrorGroups = 0
        
        foreach ($group in $exclusionGroups) {
            try {
                # Check if group already exists
                $existingGroup = $CurrentInfo | Where-Object { $_.displayName -eq $group.Name }
                
                if (-not $existingGroup) {
                    # Create mail nickname (alphanumeric only, max 64 chars)
                    $mailNickname = ($group.Name -replace '[^a-zA-Z0-9]', '').Substring(0, [Math]::Min(64, ($group.Name -replace '[^a-zA-Z0-9]', '').Length))
                    
                    $groupBody = @{
                        displayName     = $group.Name
                        description     = $group.Description
                        mailEnabled     = $false
                        mailNickname    = $mailNickname
                        securityEnabled = $true
                        groupTypes      = @()
                    } | ConvertTo-Json -Compress

                    $null = New-GraphPostRequest -uri 'https://graph.microsoft.com/v1.0/groups' -tenantid $tenant -type POST -body $groupBody
                    Write-LogMessage -API 'Standards' -tenant $tenant -message "Created Joey CA exclusion group: $($group.Name)" -sev Info
                    $CreatedGroups++
                }
                else {
                    $ExistingGroups++
                }
            }
            catch {
                Write-LogMessage -API 'Standards' -tenant $tenant -message "Failed to create Joey CA exclusion group $($group.Name): $($_.Exception.Message)" -sev Error
                $ErrorGroups++
            }
        }
        
        # Add break glass account to CA-BreakGlassAccounts - Exclude if specified
        if ($Settings.BreakGlassUPN) {
            try {
                Start-Sleep -Seconds 5  # Wait for group creation to complete
                $breakGlassGroup = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq 'CA-BreakGlassAccounts - Exclude'" -tenantid $tenant
                $breakGlassUser = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$($Settings.BreakGlassUPN)'" -tenantid $tenant
                
                if ($breakGlassGroup.value.Count -gt 0 -and $breakGlassUser.value.Count -gt 0) {
                    $memberBody = @{
                        '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($breakGlassUser.value[0].id)"
                    } | ConvertTo-Json -Compress
                    
                    try {
                        $null = New-GraphPostRequest -uri "https://graph.microsoft.com/v1.0/groups/$($breakGlassGroup.value[0].id)/members/`$ref" -tenantid $tenant -type POST -body $memberBody
                        Write-LogMessage -API 'Standards' -tenant $tenant -message "Added break glass account $($Settings.BreakGlassUPN) to CA-BreakGlassAccounts - Exclude" -sev Info
                    }
                    catch {
                        if ($_.Exception.Message -like '*already exist*') {
                            Write-LogMessage -API 'Standards' -tenant $tenant -message "Break glass account $($Settings.BreakGlassUPN) already in CA-BreakGlassAccounts - Exclude" -sev Info
                        }
                        else {
                            throw
                        }
                    }
                }
            }
            catch {
                Write-LogMessage -API 'Standards' -tenant $tenant -message "Failed to add break glass account: $($_.Exception.Message)" -sev Error
            }
        }
        
        Write-LogMessage -API 'Standards' -tenant $tenant -message "Joey CA Baseline: Created $CreatedGroups groups, $ExistingGroups already existed, $ErrorGroups errors" -sev Info
    }
    
    If ($Settings.alert -eq $true -or $Settings.report -eq $true) {
        $MissingGroups = @()
        
        foreach ($group in $exclusionGroups) {
            $existingGroup = $CurrentInfo | Where-Object { $_.displayName -eq $group.Name }
            if (-not $existingGroup) {
                $MissingGroups += $group.Name
            }
        }
        
        $StateMessage = if ($MissingGroups.Count -eq 0) {
            'All Joey CA Baseline exclusion groups exist'
        }
        else {
            "Missing $($MissingGroups.Count) Joey CA Baseline exclusion groups: $($MissingGroups -join ', ')"
        }
        
        if ($Settings.alert -eq $true) {
            if ($MissingGroups.Count -gt 0) {
                Write-LogMessage -API 'Standards' -tenant $tenant -message $StateMessage -sev Alert
            }
        }
        
        if ($Settings.report -eq $true) {
            Add-CIPPBPAField -FieldName 'JoeyCAExclusionGroups' -FieldValue $StateMessage -StoreAs string -Tenant $tenant
        }
    }
}
