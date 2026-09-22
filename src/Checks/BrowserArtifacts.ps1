function Invoke-ProfileDatabaseQuery {
    param([string]$Path,[string]$Query)
    if(-not(Test-AllowedLocalPath $Path)-or(Get-FilePresence $Path)-ne'Present'){return}
    if(-not('StealthPrivesc.NativeSqlite'-as[type])){Add-Type -Path (Join-Path $script:ModuleRoot 'NativeSqlite.cs')}
    try{$result=[StealthPrivesc.NativeSqlite]::Query($Path,$Query,$script:Context.MaxItems,$script:Context.CommandTimeoutSeconds);if($result.Truncated){Set-CheckPartial 'Browser database results exceeded MaxItems.'};return ,$result.Rows}
    catch{Set-CheckPartial "Read-only browser database query failed (locked, schema or platform unavailable): $Path"}
}
function Get-RedactedUrl {
    param([string]$Value)
    $uri=$null;if([Uri]::TryCreate($Value,[UriKind]::Absolute,[ref]$uri)-and$uri.Scheme-in@('https','http','ftp')){return @{Scheme=$uri.Scheme;Host=$uri.DnsSafeHost;Port=$uri.Port;PathAndQuery='[REDACTED]'}}
    @{Value='[REDACTED]';Present=(-not[string]::IsNullOrWhiteSpace($Value))}
}
function Invoke-BrowserArtifactCheck {
    param([int]$Id)
    if($Id-eq136){$path='HKCU:\Software\Microsoft\Internet Explorer\TypedURLs';try{$key=Get-Item -LiteralPath $path -ErrorAction Stop;try{foreach($name in $key.GetValueNames()){Add-Evidence ($path+'/'+$name) 'Typed URL registry entry; path/query redacted.' (Get-RedactedUrl ([string]$key.GetValue($name)))}}finally{$key.Close()}}catch [System.Management.Automation.ItemNotFoundException]{}}
    if($Id-eq98-and-not('StealthPrivesc.NativeSecrets'-as[type])){Add-Type -Path (Join-Path $script:ModuleRoot 'NativeSecrets.cs')}
    foreach($profile in Get-ProfileRoots){
        foreach($root in @("$profile\AppData\Local\Google\Chrome\User Data","$profile\AppData\Local\Microsoft\Edge\User Data","$profile\AppData\Local\BraveSoftware\Brave-Browser\User Data","$profile\AppData\Roaming\Opera Software")){
            $protectedKey=$null
            if($Id-eq98){$statePath=Join-Path $root 'Local State';if((Get-FilePresence $statePath)-eq'Present'){try{if((Get-Item -LiteralPath $statePath).Length-le$script:Context.MaxFileBytes){$state=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json;$encoded=Get-OptionalProperty (Get-OptionalProperty $state 'os_crypt') 'encrypted_key';if($encoded){$protectedKey=[Convert]::FromBase64String($encoded)}}}catch{Set-CheckPartial 'Browser key metadata could not be decoded.'}}}
            foreach($file in Get-BoundedFiles @($root) -Depth 2 -Pattern '^(Login Data|History|Bookmarks|Local State|Session_.*|Tabs_.*)$'){
                if($Id-eq98-and$file.Name-eq'Login Data'){
                    $rows=Invoke-ProfileDatabaseQuery $file.FullName 'SELECT origin_url,length(username_value),length(password_value),hex(password_value) FROM logins'
                    foreach($row in $rows){$cipher=New-Object byte[] ($row[3].Length/2);try{for($i=0;$i-lt$cipher.Length;$i++){$cipher[$i]=[Convert]::ToByte($row[3].Substring($i*2,2),16)};$probe=[StealthPrivesc.NativeSecrets]::Browser($protectedKey,$cipher);Add-Evidence $file.FullName 'Browser saved-login recovery probe under the current token; plaintext erased inside native collector.' @{Origin=(Get-RedactedUrl $row[0]);UserNamePresent=([int]$row[1]-gt0);EncryptedPasswordPresent=([int]$row[2]-gt0);Recovery=$probe} $(if($probe.Recovered){'Medium'}else{'Low'});if($probe.Method-eq'AppBoundUnsupported'){Set-CheckPartial 'App-bound browser encryption is not bypassed; those saved logins remain unverified.'}}finally{[Array]::Clear($cipher,0,$cipher.Length);$row[3]=$null}}
                }
                elseif($Id-eq98-and$file.Name-eq'Local State'){
                    if($file.Length-gt$script:Context.MaxFileBytes){Set-CheckPartial 'Browser Local State exceeds MaxFileBytes.';continue}
                    try{$state=Get-Content -LiteralPath $file.FullName -Raw|ConvertFrom-Json;$crypto=Get-OptionalProperty $state 'os_crypt';Add-Evidence $file.FullName 'Browser encryption-key storage indicators; app-bound encryption is distinguished from user DPAPI.' @{DpapiKeyPresent=([bool](Get-OptionalProperty $crypto 'encrypted_key'));AppBoundKeyPresent=([bool](Get-OptionalProperty $crypto 'app_bound_encrypted_key'));Value='[REDACTED]'}}catch{Set-CheckPartial 'Browser Local State could not be parsed.'}
                }
                elseif($Id-eq136-and$file.Name-eq'History'){
                    $rows=Invoke-ProfileDatabaseQuery $file.FullName 'SELECT url,visit_count,last_visit_time,typed_count FROM urls ORDER BY last_visit_time DESC'
                    foreach($row in $rows){Add-Evidence $file.FullName 'Browser history and typed URL record; paths/queries redacted.' @{Origin=(Get-RedactedUrl $row[0]);VisitCount=$row[1];LastVisitChromeMicroseconds=$row[2];TypedCount=$row[3]}}
                }
                elseif($Id-eq136-and$file.Name-eq'Bookmarks'){
                    if($file.Length-gt$script:Context.MaxFileBytes){Set-CheckPartial 'Bookmark file exceeds MaxFileBytes.';continue}
                    try{$document=Get-Content -LiteralPath $file.FullName -Raw|ConvertFrom-Json;$queue=New-Object 'System.Collections.Generic.Queue[object]';foreach($rootProperty in $document.roots.PSObject.Properties){$queue.Enqueue($rootProperty.Value)};$count=0;while($queue.Count-and$count-lt$script:Context.MaxItems){$node=$queue.Dequeue();$count++;if($node.PSObject.Properties['url']){Add-Evidence $file.FullName 'Browser bookmark; title and URL path/query redacted.' @{Origin=(Get-RedactedUrl $node.url);Title='[REDACTED]'}};if($node.PSObject.Properties['children']){foreach($child in $node.children){$queue.Enqueue($child)}}};if($queue.Count){Set-CheckPartial 'Bookmark traversal reached MaxItems.'}}catch{Set-CheckPartial 'Bookmarks could not be parsed.'}
                }
                elseif($Id-eq136-and$file.Name-match'^(Session_|Tabs_)'){Add-ReadableArtifact $file.FullName 'Browser session/open-tab backing store';Add-BrowserSessionEvidence $file.FullName}
            }
        }
        foreach($file in Get-BoundedFiles @("$profile\AppData\Roaming\Mozilla\Firefox\Profiles") -Depth 2 -Pattern '^(logins.json|key4.db|places.sqlite|recovery.jsonlz4|sessionstore.jsonlz4)$'){
            if($Id-eq98-and$file.Name-eq'logins.json'){
                if($file.Length-gt$script:Context.MaxFileBytes){Set-CheckPartial 'Firefox login file exceeds MaxFileBytes.';continue}
                $probes=@(Invoke-FirefoxRecoveryProbe $file.FullName);foreach($probe in $probes){Add-Evidence $file.FullName 'Firefox NSS password recovery probe; returned plaintext erased before reporting.' $probe $(if($probe.Recovered){'Medium'}else{'Information'})}
                try{$data=Get-Content -LiteralPath $file.FullName -Raw|ConvertFrom-Json;foreach($login in Get-Limited @($data.logins)){Add-Evidence $file.FullName 'Firefox stored login; NSS-encrypted fields are not collected.' @{Origin=(Get-RedactedUrl $login.hostname);EncryptedUserNamePresent=([bool]$login.encryptedUsername);EncryptedPasswordPresent=([bool]$login.encryptedPassword);Value='[REDACTED]'} 'Low'}}catch{Set-CheckPartial 'Firefox login JSON could not be parsed.'}
            }elseif($Id-eq136-and$file.Name-eq'places.sqlite'){
                $rows=Invoke-ProfileDatabaseQuery $file.FullName 'SELECT url,visit_count,last_visit_date FROM moz_places ORDER BY last_visit_date DESC';foreach($row in $rows){Add-Evidence $file.FullName 'Firefox browsing record; URL paths and queries redacted.' @{Origin=(Get-RedactedUrl $row[0]);VisitCount=$row[1];LastVisitUnixMicroseconds=$row[2]}}
            }elseif(($Id-eq98-and$file.Name-eq'key4.db')-or($Id-eq136-and$file.Name-like'*.jsonlz4')){Add-ReadableArtifact $file.FullName 'Firefox credential/session backing store';if($Id-eq136){Add-BrowserSessionEvidence $file.FullName -Firefox}}
        }
    }
}
