param([string]$Out, [string]$Stop)
# Runs alongside the CPU suite: about every 2 s one line "time,power,processor performance %" until the file $Stop
# exists. A step whose lines show anything but mains power makes the session invalid, and the performance column
# shows whether the processor throttled during the step.
Add-Type -AssemblyName System.Windows.Forms
while (-not (Test-Path $Stop)) {
  $ps = [System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus
  $perf = $null
  try { $perf = [math]::Round((Get-Counter '\Processor Information(_Total)\% Processor Performance' -ErrorAction Stop).CounterSamples[0].CookedValue, 1) } catch {}
  "{0},{1},{2}" -f (Get-Date).ToUniversalTime().ToString('o'), $ps, $perf | Add-Content -Path $Out
  Start-Sleep -Seconds 1
}
