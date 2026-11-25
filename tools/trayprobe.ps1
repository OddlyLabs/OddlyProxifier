param([int]$Command = 0, [switch]$Find)
# Finds the tray window of a running OddlyProxifier and, with -Command N,
# sends it the menu command N (1 open, 2 toggle interception, 3 exit).
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class TrayProbe {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindowW(string cls, string title);
    [DllImport("user32.dll")]
    public static extern bool PostMessageW(IntPtr hwnd, uint msg, IntPtr wp, IntPtr lp);
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
}
"@
$h = [TrayProbe]::FindWindowW("OddlyProxifierTray", "OddlyProxifier")
if ($h -eq [IntPtr]::Zero) { "window: none"; exit 1 }
$procId = 0
[void][TrayProbe]::GetWindowThreadProcessId($h, [ref]$procId)
"window: found, pid $procId"
if ($Command -gt 0) {
    [void][TrayProbe]::PostMessageW($h, 0x8003, [IntPtr]$Command, [IntPtr]::Zero)
    "sent command $Command"
}
