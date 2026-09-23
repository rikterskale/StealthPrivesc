function Invoke-CodeIntegrityCheck {
    $data=Get-ReferenceDocument $script:Context.DriverDatabasePath 'LOLDrivers';if(-not$data){return}
    $active=@();$ciTool=Join-Path $env:SystemRoot 'System32\CiTool.exe'
    if((Get-FilePresence $ciTool)-eq'Present'){try{$active=@((Invoke-ReadOnlyCommand $ciTool '-lp -json'|ConvertFrom-Json).Policies);foreach($policy in $active){Add-Evidence $policy.PolicyID 'Code Integrity runtime policy state.' ($policy|Select-Object PolicyID,BasePolicyID,FriendlyName,IsEnforced,IsAuthorized,IsOnDisk)}}catch{Set-CheckPartial 'CiTool runtime policy state unavailable.' -ErrorRecord $_}}
    else{Set-CheckPartial 'CiTool is unavailable; on-disk policy presence cannot establish enforcement.'}
    $paths=@("$env:SystemRoot\System32\CodeIntegrity\DriversIPolicy.p7b","$env:SystemRoot\System32\CodeIntegrity\SiPolicy.p7b")
    $paths+=@(Get-BoundedFiles @("$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active") -Depth 0 -Pattern '\.cip$'|ForEach-Object FullName)
    $policies=@(foreach($path in $paths|Select-Object -Unique){if((Get-FilePresence $path)-ne'Present'){continue};try{$parsed=Read-CIPolicyIsolated $path;$policy=$parsed.Policy;$id=Get-OptionalProperty $policy 'PolicyID';if(-not$id){$id=$policy.PolicyTypeID};$runtime=@($active|Where-Object{([string]$_.PolicyID).Trim('{}')-eq([string]$id).Trim('{}')});$enforced=$runtime.Count-gt0-and$runtime[0].IsEnforced;if($parsed.Incomplete){Set-CheckPartial 'Some policy sections were not decoded; policy conclusions are incomplete.'};Add-Evidence $path 'Decoded Code Integrity policy; driver signing scenario is evaluated separately from user-mode rules.' @{PolicyID=$id;Enforced=$enforced;DecodeIncomplete=$parsed.Incomplete;FileRules=@(Get-OptionalProperty $policy 'FileRules').Count;SignerRules=@(Get-OptionalProperty $policy 'SignerRules').Count};[pscustomobject]@{Path=$path;Policy=$policy;Enforced=$enforced;Incomplete=$parsed.Incomplete}}catch{Set-CheckPartial "Code Integrity policy parsing failed: $path" -ErrorRecord $_}})
    if(-not$policies.Count){Set-CheckPartial 'No Code Integrity policy could be decoded.';return}
    foreach($sample in Get-Limited @($data.Entries|Where-Object Category -match 'vulnerable')){
        $matches=@(foreach($policy in $policies){foreach($match in Get-CIDenyMatches $policy.Policy $sample){[pscustomobject]@{Policy=$policy.Path;Rule=$match.RuleId;Kind=$match.Kind;Conditional=$match.Conditional;Enforced=$policy.Enforced;DecodeIncomplete=$policy.Incomplete}}})
        $confirmed=@($matches|Where-Object{$_.Enforced-and-not$_.Conditional-and-not$_.DecodeIncomplete})
        $state=if($confirmed.Count){'ExplicitEnforcedDenyMatch'}elseif($matches.Count){'ConditionalOrInactiveDenyMatch'}else{'NoExplicitDenyMatch'}
        Add-Evidence $sample.SHA256 'Known vulnerable driver compared with decoded local deny rules. A missing deny match does not establish load permission: allowlists, signer conditions and other kernel protections also apply.' @{ReferenceId=$sample.Id;State=$state;Matches=$matches} $(if($state-eq'NoExplicitDenyMatch'){'Low'}else{'Information'})
    }
}
