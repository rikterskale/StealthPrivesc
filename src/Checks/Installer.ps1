function Invoke-InstallerCheck {
    param([int]$Id)
    $allowlist=@()
    if($Id-eq49){
        Add-RegistryEvidence 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' @('SecureRepairPolicy','DisableLUAInRepair')
        try{$key=Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\SecureRepairWhitelist' -ErrorAction Stop;try{$allowlist=@($key.GetValueNames())}finally{$key.Close()}}
        catch [System.Management.Automation.ItemNotFoundException]{return}
        foreach($product in $allowlist){Add-Evidence $product 'MSI repair allowlist entry.'}
        if(-not$allowlist.Count){return}
    }
    $installer=New-Object -ComObject WindowsInstaller.Installer -ErrorAction Stop
    try{
        foreach($file in Get-BoundedFiles @("$env:SystemRoot\Installer") -Depth 0 -Pattern '\.msi$'){
            $database=$null;$view=$null;$record=$null
            try{
                $database=$installer.OpenDatabase($file.FullName,0) # msiOpenDatabaseModeReadOnly
                if($Id-eq49){
                    $view=$database.OpenView('SELECT `Value` FROM `Property` WHERE `Property` = ''ProductCode''');$view.Execute();$record=$view.Fetch()
                    $productCode=if($record){$record.StringData(1)}else{''}
                    if($record){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record);$record=$null}
                    $view.Close();[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view);$view=$null
                    if($productCode-notin$allowlist){continue}
                }
                $sequence=@{}
                $sequenceView=$null;$sequenceRow=$null
                try{
                    $sequenceView=$database.OpenView('SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence`');$sequenceView.Execute()
                    while($null-ne($sequenceRow=$sequenceView.Fetch())){try{$sequence[$sequenceRow.StringData(1)]=@{Condition=$sequenceRow.StringData(2);Sequence=$sequenceRow.IntegerData(3)}}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($sequenceRow);$sequenceRow=$null}}
                }catch{Set-CheckPartial 'An MSI execute sequence could not be inspected.'}
                finally{if($sequenceRow){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($sequenceRow)};if($sequenceView){$sequenceView.Close();[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($sequenceView)}}
                $view=$database.OpenView('SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`');$view.Execute()
                $count=0
                while($null-ne($record=$view.Fetch())){
                    try{
                        $count++;if($count-gt$script:Context.MaxItems){Set-CheckPartial 'MSI custom-action limit reached.';break}
                        $type=$record.IntegerData(2)
                        if(($type-band0x400)-and($type-band0x800)){
                            $name=$record.StringData(1);$target=$record.StringData(4);$scheduled=$sequence.ContainsKey($name);$condition=if($scheduled){$sequence[$name].Condition}else{''}
                            $indicators=Get-MsiActionIndicators $type $scheduled $condition $target
                            Add-Evidence $file.FullName 'Privileged MSI custom action assessed against execution sequence, repair-condition and target markers. Dynamic property values and MSI condition evaluation require installation context.' @{Action=$name;Type=$type;SourceReference=$record.StringData(3);Sequence=$(if($scheduled){$sequence[$name].Sequence});Indicators=$indicators;Target='[REDACTED]';Condition='[REDACTED]'} $(if($scheduled){'Medium'}else{'Low'})
                            if(($type-band0x3f)-in@(2,18,34,50)){foreach($path in Get-ReferencedPaths (Get-ExecutablePath $target) $target ([Environment]::SystemDirectory)){if($path-notmatch'\[[^\]]+\]'){Add-ExecutableAccess $path 'Writable statically resolved privileged MSI action target.'}}}
                        }
                    }finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record);$record=$null}
                }
            }catch{Set-CheckPartial 'Some MSI databases lack a CustomAction table or could not be read.'}
            finally{if($record){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)};if($view){$view.Close();[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)};if($database){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)}}
        }
    }finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)}
}
function Get-MsiActionIndicators {
    param([int]$Type,[bool]$Scheduled,[string]$Condition,[string]$Target)
    [pscustomobject]@{
        Deferred=[bool]($Type-band0x400);NoImpersonate=[bool]($Type-band0x800);Rollback=[bool]($Type-band0x100);Commit=[bool]($Type-band0x200)
        InExecuteSequence=$Scheduled;MentionsRepair=($Condition-match'(?i)\bREINSTALL\b|\bInstalled\b');NoCondition=([string]::IsNullOrWhiteSpace($Condition))
        DynamicProperties=($Target-match'\[[^\]]+\]');ShellOrScript=($Target-match'(?i)\b(cmd|powershell|pwsh|wscript|cscript)(\.exe)?\b');SecretMarker=($Target-match'(?i)(password|passwd|token|secret)\s*[:=]')
    }
}
