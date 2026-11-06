param([Parameter(Mandatory=$true)][string]$RequestPath, [Parameter(Mandatory=$true)][string]$ResponsePath)
$ErrorActionPreference = 'Stop'
$response = $null
try {
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
    Add-Type -AssemblyName WindowsBase
    $request = Get-Content -LiteralPath $RequestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $walker = [Windows.Automation.TreeWalker]::ControlViewWalker
    $desktop = [Windows.Automation.AutomationElement]::RootElement
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $nodes = [Collections.Generic.List[object]]::new()
    $queue = [Collections.Generic.Queue[object]]::new()
    $queue.Enqueue(@{element=$desktop; depth=0; window=0})
    $visited = 0
    $skipped = 0
    $skippedMessages = [Collections.Generic.List[string]]::new()
    $found = $null
    # 単一providerの停止は親Python側のタイムアウトで打ち切り、全体を巻き込まない。
    while ($queue.Count -gt 0 -and $visited -lt 600 -and $clock.ElapsedMilliseconds -lt 4000) {
        $item = $queue.Dequeue()
        $element = $item.element
        $visited++
        try {
            $current = $element.Current
            $window = $item.window
            if ($item.depth -eq 1) { $window = $current.NativeWindowHandle }
            if ($item.depth -eq 1 -and $request.window_handle -and $window -ne [long]$request.window_handle) { continue }
            if ($item.depth -gt 0 -and -not $current.IsOffscreen) {
                $runtimeId = [string]::Join(',', $element.GetRuntimeId())
                $controlType = $current.ControlType.ProgrammaticName
                $processStart = (Get-Process -Id $current.ProcessId -ErrorAction Stop).StartTime.ToUniversalTime().Ticks.ToString()
                if ($request.mode -eq 'observe') {
                    $rect = $current.BoundingRectangle
                    $point = [Windows.Point]::new(0, 0)
                    $hasPoint = $element.TryGetClickablePoint([ref]$point)
                    $patterns = @($element.GetSupportedPatterns() | ForEach-Object { $_.ProgrammaticName })
                    $nodes.Add(@{runtime_id=$runtimeId; name=$current.Name; control_type=$controlType;
                        automation_id=$current.AutomationId; process_id=$current.ProcessId; process_start=$processStart;
                        window_handle=$window; enabled=$current.IsEnabled; offscreen=$current.IsOffscreen;
                        rectangle=@($rect.Left,$rect.Top,$rect.Right,$rect.Bottom); patterns=$patterns;
                        clickable_point=$(if ($hasPoint) { @($point.X,$point.Y) } else { $null })})
                } elseif ($runtimeId -eq $request.target.runtime_id -and $current.ProcessId -eq $request.target.process_id -and
                    $processStart -eq $request.target.process_start -and $window -eq $request.target.window_handle -and
                    $current.Name -ceq $request.target.name -and $current.AutomationId -ceq $request.target.automation_id -and
                    $controlType -ceq $request.target.control_type) {
                    $found = $element
                    break
                }
            }
            if ($item.depth -lt 16) {
                $child = $walker.GetFirstChild($element)
                $siblings = 0
                while ($null -ne $child -and $siblings -lt 200 -and $queue.Count -lt 600 -and $clock.ElapsedMilliseconds -lt 4000) {
                    $queue.Enqueue(@{element=$child; depth=($item.depth+1); window=$window})
                    $child = $walker.GetNextSibling($child)
                    $siblings++
                }
            }
        } catch { $skipped++; if ($skippedMessages.Count -lt 3) { $skippedMessages.Add($_.Exception.Message) }; continue }
    }
    if ($request.mode -eq 'observe') {
        $response = @{status='observed'; elements=@($nodes.ToArray()); visited=$visited;
            partial=($queue.Count -gt 0 -or $skipped -gt 0); skipped=$skipped; skipped_messages=@($skippedMessages.ToArray()); elapsed_ms=$clock.ElapsedMilliseconds}
    } else {
        if ($null -eq $found) { throw 'Target disappeared or changed; observe again' }
        if (-not $found.Current.IsEnabled -or $found.Current.IsOffscreen) { throw 'Target is not currently available' }
        switch ($request.operation) {
            'point' {
                $point = [Windows.Point]::new(0, 0)
                if (-not $found.TryGetClickablePoint([ref]$point)) { throw 'No clickable point; use image observation' }
                $response = @{status='resolved'; point=@($point.X,$point.Y); operation='point'; input_sent=$false}
            }
            'invoke' { ([Windows.Automation.InvokePattern]$found.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern)).Invoke() }
            'set_value' { ([Windows.Automation.ValuePattern]$found.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)).SetValue([string]$request.value) }
            'select' { ([Windows.Automation.SelectionItemPattern]$found.GetCurrentPattern([Windows.Automation.SelectionItemPattern]::Pattern)).Select() }
            default { throw 'Unsupported UIA operation' }
        }
        if ($null -eq $response) { $response = @{status='performed'; operation=$request.operation; application_result_verified=$false} }
    }
} catch {
    $response = @{status='image_fallback'; message=$_.Exception.Message; analysis_halt_required=$false}
}
$json = ConvertTo-Json -InputObject $response -Depth 10 -Compress
[IO.File]::WriteAllText($ResponsePath, $json, [Text.UTF8Encoding]::new($false))
