function Invoke-SearchIndexCheck {
    Invoke-InventoryCheck 139
    $connection=$null;$records=$null
    try{
        $connection=New-Object -ComObject ADODB.Connection
        $connection.ConnectionTimeout=$script:Context.CommandTimeoutSeconds
        $connection.CommandTimeout=$script:Context.CommandTimeoutSeconds
        $connection.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';")
        $scopes=@(foreach($root in Get-SearchRoots){if(Test-AllowedLocalPath $root){"SCOPE='file:"+$root.Replace("'","''")+"'"}})
        if(-not$scopes.Count){return}
        $query='SELECT TOP '+$script:Context.MaxItems+' System.ItemPathDisplay, System.ItemTypeText, System.DateModified FROM SYSTEMINDEX WHERE '+($scopes-join' OR ')
        $records=$connection.Execute($query)
        $count=0
        while(-not$records.EOF-and$count-lt$script:Context.MaxItems){
            Add-Evidence ([string]$records.Fields.Item(0).Value) 'Windows Search Index result within configured search roots.' @{Type=[string]$records.Fields.Item(1).Value;Modified=[string]$records.Fields.Item(2).Value}
            $records.MoveNext();$count++
        }
        if($count-ge$script:Context.MaxItems){Set-CheckPartial 'Search Index query reached MaxItems.'}
    }catch{Set-CheckPartial 'Windows Search Index provider is unavailable or inaccessible.' -ErrorRecord $_}
    finally{if($records){if($records.State-ne0){$records.Close()};[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($records)};if($connection){if($connection.State-ne0){$connection.Close()};[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($connection)}}
}
