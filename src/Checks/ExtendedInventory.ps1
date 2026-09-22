function Invoke-ExtendedInventoryCheck {
    param([int]$Id)
    switch($Id){
        56 {
            foreach($fix in Get-Limited @(Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop)){Add-Evidence $fix.HotFixID 'Installed hotfix.' ($fix|Select-Object HotFixID,Description,InstalledOn)}
            $session=$null;$searcher=$null;$history=$null
            try{
                $session=New-Object -ComObject Microsoft.Update.Session
                $searcher=$session.CreateUpdateSearcher();$count=$searcher.GetTotalHistoryCount()
                if($count){$history=$searcher.QueryHistory(0,[Math]::Min($count,$script:Context.MaxItems));foreach($entry in $history){Add-Evidence $entry.Title 'Windows Update history; failed and uninstallation events are distinguished.' @{Date=$entry.Date;Operation=$entry.Operation;ResultCode=$entry.ResultCode;HResult=$entry.HResult;UpdateId=$entry.UpdateIdentity.UpdateID;Revision=$entry.UpdateIdentity.RevisionNumber}}}
                if($count-gt$script:Context.MaxItems){Set-CheckPartial 'Windows Update history truncated to newest MaxItems.'}
            }catch{Set-CheckPartial 'Windows Update history API unavailable.'}
            finally{foreach($com in @($history,$searcher,$session)){if($com){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($com)}}}
            try{foreach($package in Get-Limited @(Get-WindowsPackage -Online -ErrorAction Stop)){Add-Evidence $package.PackageName 'Component-based servicing package.' ($package|Select-Object PackageState,ReleaseType,InstallTime)}}catch{Set-CheckPartial 'CBS package inventory requires DISM and sufficient access.'}
        }
        {$_-in@(58,61)} {
            foreach($driver in Get-Limited @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop)){Add-Evidence $driver.DeviceName 'PnP driver metadata, including catalog signing.' ($driver|Select-Object DeviceName,DriverVersion,DriverDate,DriverProviderName,InfName,IsSigned,Signer)}
            foreach($driver in Get-Limited @(Get-InstalledDriverFiles)){
                if(-not(Test-AllowedLocalPath $driver.Path)){continue}
                try{
                    $signature=Get-AuthenticodeSignature -LiteralPath $driver.Path -ErrorAction Stop
                    $certificate=$signature.SignerCertificate;$weak=$false;$algorithm=$null;$bits=$null
                    if($certificate){$algorithm=$certificate.SignatureAlgorithm.Value;$weak=$algorithm-in@('1.2.840.113549.1.1.4','1.2.840.113549.1.1.5','1.2.840.10040.4.3');try{$bits=$certificate.PublicKey.Key.KeySize;if($bits-lt2048-and$certificate.PublicKey.Oid.Value-eq'1.2.840.113549.1.1.1'){$weak=$true}}catch{}}
                    Add-Evidence $driver.Path 'Installed system driver signature/trust and signer strength; signer algorithm is distinct from the image digest. Catalog signatures are resolved by Windows.' @{Service=$driver.Name;State=$driver.State;SignatureStatus=[string]$signature.Status;SignatureType=[string]$signature.SignatureType;Signer=$(if($certificate){$certificate.Subject});SignerSignatureAlgorithm=$algorithm;SignerKeyBits=$bits;WeakSigner=$weak;Timestamped=($null-ne$signature.TimeStamperCertificate)} $(if($Id-eq61-and($signature.Status-ne'Valid'-or$weak)){'Medium'}else{'Information'})
                }catch{Set-CheckPartial 'A driver signature could not be evaluated.'}
            }
        }
    }
}
