function Get-CommandShape {
    param([string]$CommandLine)
    if(-not$CommandLine){return $null}
    $executable=Get-ExecutablePath $CommandLine
    $arguments=@([StealthPrivesc.NativeInspection]::CommandArguments($CommandLine))
    $switches=@(foreach($argument in $arguments|Select-Object -Skip 1){
        if($argument-match'^(--?[A-Za-z][A-Za-z0-9_-]*|/[A-Za-z][A-Za-z0-9_-]*)(?:[:=].*)?$'){$Matches[1]}
    })
    [pscustomobject]@{Executable=$executable;Switches=$switches;Arguments='[REDACTED]';ArgumentCount=[Math]::Max(0,$arguments.Count-1)}
}
function Get-EventFields {
    param([object]$Event,[string[]]$Names)
    $document=New-Object Xml.XmlDocument
    $document.XmlResolver=$null
    $document.LoadXml($Event.ToXml())
    $fields=@{}
    foreach($node in $document.SelectNodes('//*[local-name()="EventData"]/*[local-name()="Data"]')){
        $name=$node.GetAttribute('Name')
        if($name-in$Names){$fields[$name]=$node.InnerText}
    }
    return $fields
}
