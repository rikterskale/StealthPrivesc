function Add-BrowserSessionEvidence {
    param([string]$Path,[switch]$Firefox)
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop
    if($file.Length-gt$script:Context.MaxFileBytes){Set-CheckPartial 'Browser session file exceeds MaxFileBytes.';return}
    if(-not('StealthPrivesc.NativeSessions'-as[type])){Add-Type -Path (Join-Path $script:ModuleRoot 'NativeSessions.cs')}
    try{
        $bytes=[IO.File]::ReadAllBytes($Path)
        if($Firefox){
            $document=[StealthPrivesc.NativeSessions]::Firefox($bytes,$script:Context.MaxFileBytes)|ConvertFrom-Json
            foreach($window in @($document.windows)){foreach($tab in Get-Limited @($window.tabs)){if($tab.index-ge1-and$tab.index-le@($tab.entries).Count){Add-Evidence $Path 'Firefox tab from a persisted session snapshot; current live state may differ.' @{Origin=(Get-RedactedUrl $tab.entries[$tab.index-1].url);SelectedNavigation=$tab.index}}}}
        }else{foreach($tab in Get-Limited @([StealthPrivesc.NativeSessions]::Chromium($bytes,$script:Context.MaxItems))){Add-Evidence $Path 'Chromium tab navigation from persisted session commands; current live/window state may differ.' @{TabId=$tab.TabId;NavigationIndex=$tab.Index;Selected=$tab.Selected;Origin=(Get-RedactedUrl $tab.Url)}}}
    }catch{Set-CheckPartial 'Browser session is encrypted, unsupported, malformed or outside configured limits.'}
}
