function Read-RegistryPolicyMetadata {
    param([string]$Path)
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop
    if($file.Length-gt$script:Context.MaxFileBytes){Set-CheckPartial 'Registry.pol exceeds MaxFileBytes.';return}
    $stream=[IO.File]::OpenRead($Path);$reader=New-Object IO.BinaryReader($stream,[Text.Encoding]::Unicode)
    function Read-PolString([IO.BinaryReader]$Reader){$text=New-Object Text.StringBuilder;while($true){$ch=$Reader.ReadUInt16();if($ch-eq0){break};if($text.Length-ge32768){throw 'Registry policy string too long.'};[void]$text.Append([char]$ch)};$text.ToString()}
    function Assert-PolCharacter([IO.BinaryReader]$Reader,[char]$Expected){if($Reader.ReadUInt16()-ne[int]$Expected){throw 'Invalid registry policy delimiter.'}}
    try{
        if($reader.ReadUInt32()-ne0x67655250-or$reader.ReadUInt32()-ne1){throw 'Unsupported registry policy header.'}
        $count=0
        while($stream.Position-lt$stream.Length){
            if($count-ge$script:Context.MaxItems){Set-CheckPartial 'Registry policy entry limit reached.';break};$count++
            Assert-PolCharacter $reader '[';$key=Read-PolString $reader;Assert-PolCharacter $reader ';';$name=Read-PolString $reader;Assert-PolCharacter $reader ';';$type=$reader.ReadUInt32();Assert-PolCharacter $reader ';';$size=$reader.ReadUInt32();Assert-PolCharacter $reader ';'
            if($size-gt($stream.Length-$stream.Position)){throw 'Truncated registry policy data.'};[void]$stream.Seek($size,[IO.SeekOrigin]::Current);Assert-PolCharacter $reader ']'
            Add-Evidence $Path 'Local registry policy entry; values redacted.' @{Key=$key;Name=$name;Type=$type;Bytes=$size;Value='[REDACTED]'}
        }
    }finally{$reader.Dispose();$stream.Dispose()}
}
