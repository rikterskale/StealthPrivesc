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
                $view=$database.OpenView('SELECT `Action`, `Type` FROM `CustomAction`');$view.Execute()
                $count=0
                while($null-ne($record=$view.Fetch())){
                    try{
                        $count++;if($count-gt$script:Context.MaxItems){Set-CheckPartial 'MSI custom-action limit reached.';break}
                        $type=$record.IntegerData(2)
                        if(($type-band0x400)-and($type-band0x800)){Add-Evidence $file.FullName 'Deferred, non-impersonating MSI custom action; requires manual repair-path analysis.' @{Action=$record.StringData(1);Type=$type;Target='[OMITTED]';Deferred=$true;NoImpersonate=$true} 'Low'}
                    }finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record);$record=$null}
                }
            }catch{Set-CheckPartial 'Some MSI databases lack a CustomAction table or could not be read.'}
            finally{if($record){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)};if($view){$view.Close();[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)};if($database){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)}}
        }
    }finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)}
}
