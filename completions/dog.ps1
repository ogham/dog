# Note: This works for both Windows PowerShell 5.1 and also PowerShell 7 (Core).
# But beware that in Windows PowerShell 5.1, it has issues with completing args if they start with '-'.
# For more information about the bug, see: https://github.com/PowerShell/PowerShell/issues/2912
# In PowerShell 7+, it should work correctly.
Register-ArgumentCompleter -Native -CommandName 'dog' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    [string]$argsString = $commandAst.ToString()

    # skip the "dog", split the args afterwards as array
    [string[]]$argsArray = $argsString.Split([char[]]@(' ', '=')) | Select-Object -Skip 1
    if ($argsArray -eq $null) { $argsArray = @() }

    # detect if starting a new arg (aka ending with space and asking for a completion)
    [bool]$isNewArg = $cursorPosition -gt $argsString.Length
    if ($isNewArg) {
        # if writing a new arg, add empty arg so that current and previous would be shifted
        $argsArray += ''
    }

    # get current arg (empty if starting new)
    [string]$currentArg = $argsArray[-1]
    if ([string]::IsNullOrEmpty($currentArg)) {
        $currentArg = ''
    }

    # get previous arg
    [string]$previousArg = $argsArray[-2]
    if ([string]::IsNullOrEmpty($previousArg)) {
        $previousArg = ''
    }

    [string[]]$dnsTypeValues = @('A', 'AAAA', 'CAA', 'CNAME', 'HINFO', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT')

    [string[]]$completions = @()
    [bool]$isOptionValue = $argsString.EndsWith('=')

    # complete option value
    switch -Regex ($previousArg) {
        '^(-q|--query)'       { $isOptionValue = $true }
        '^(-t|--type)'        { $isOptionValue = $true; $completions += $dnsTypeValues }
        '^(-n|--nameserver)'  { $isOptionValue = $true }
        '^(--class)'          { $isOptionValue = $true; $completions += @('IN', 'CH', 'HS') }
        '^(--edns)'           { $isOptionValue = $true; $completions += @('disable', 'hide', 'show') }
        '^(--txid)'           { $isOptionValue = $true }
        '^(-Z)'               { $isOptionValue = $true; $completions += @('aa', 'ad', 'bufsize=', 'cd') }
        '^(--color|--colour)' { $isOptionValue = $true; $completions += @('always', 'automatic', 'never') }
    }

    # detect whether to complete option value
    if ($isOptionValue) {
        if (!$isNewArg) {
            # if using =, complete including the option name and =
            $completions = $completions | ForEach-Object { "$previousArg=$_" }
        }
    } 
    else {
        # if not completing option value, offer DNS type values first
        $completions += $dnsTypeValues

        # complete option name
        [string[]]$allOptions = @(
            '-q', '--query',
            '-t', '--type',
            '-n', '--nameserver',
            '--class',
            '--edns',
            '--txid',
            '-Z',
            '-U', '--udp',
            '-T', '--tcp',
            '-S', '--tls',
            '-H', '--https',
            '-1', '--short',
            '-J', '--json',
            '--color', '--colour',
            '--seconds',
            '--time',
            '-?', '--help',
            '-v', '--version'
        ) | Sort-Object

        $completions += $allOptions
    }

    if ($completions.Count -gt 0) {
        # narrow down completions by like* matching
        return $completions -like "$currentArg*"
    }
}
