param([string]$Session, [string]$Label, [int]$Seconds = 20)
# One JSON line describing the machine over the next $Seconds: mean and peak total CPU load, the processes that used
# the most CPU during the window (% of the whole machine), power source and plan.
$n = [Environment]::ProcessorCount
$s = Get-Counter '\Processor(_Total)\% Processor Time', '\Process(*)\% Processor Time' -SampleInterval 1 -MaxSamples $Seconds -ErrorAction SilentlyContinue
$total = @(); $proc = @{}
foreach ($set in $s) {
  foreach ($c in $set.CounterSamples) {
    if ($c.Path -like '*\processor(_total)\*') { $total += $c.CookedValue; continue }
    $name = $c.InstanceName
    if ($name -in @('_total', 'idle')) { continue }
    if (-not $proc.ContainsKey($name)) { $proc[$name] = 0.0 }
    $proc[$name] += $c.CookedValue / $n / $Seconds
  }
}
Add-Type -AssemblyName System.Windows.Forms
$ps = [System.Windows.Forms.SystemInformation]::PowerStatus
$plan = (powercfg /getactivescheme) -replace '.*\((.*)\).*', '$1'
$top = $proc.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { "{0}:{1:N1}" -f $_.Key, $_.Value }
[pscustomobject]@{
  session = $Session; label = $Label; ts = (Get-Date).ToUniversalTime().ToString('o'); seconds = $Seconds
  # missing counters give null, never 0, so the idle gate cannot pass on no data
  cpuLoadMean = $(if ($total.Count -ge [math]::Floor($Seconds / 2)) { [math]::Round(($total | Measure-Object -Average).Average, 1) } else { $null })
  cpuLoadMax = $(if ($total.Count -ge [math]::Floor($Seconds / 2)) { [math]::Round(($total | Measure-Object -Maximum).Maximum, 1) } else { $null })
  onAC = ($ps.PowerLineStatus -eq 'Online'); batteryPct = [math]::Round($ps.BatteryLifePercent * 100); powerPlan = $plan
  topCpuDuringWindow = ($top -join ',')
} | ConvertTo-Json -Compress
