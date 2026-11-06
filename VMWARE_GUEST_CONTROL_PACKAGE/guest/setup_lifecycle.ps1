param([string]$Root='C:\Users\Public\r_AKanaly\dynamic',[Parameter(Mandatory=$true)][string]$GuestUser)
$ErrorActionPreference='Stop'
Start-Transcript -LiteralPath (Join-Path $Root 'setup-lifecycle.log') -Append | Out-Null
if((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch 'VMware') { throw 'Guest only' }
if(-not (Test-Path -LiteralPath (Join-Path $Root 'guest-install-marker.json'))) { throw 'Guest marker missing' }
$sid=@(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | Where-Object Name -eq $GuestUser)
if($sid.Count -ne 1) { throw 'Guest account not unique' }
$sid=$sid[0].SID
$serviceCode=@'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;
public class LifecycleService {
    [StructLayout(LayoutKind.Sequential)] struct SERVICE_STATUS { public int type,state,accepted,exit,specific,checkpoint,hint; }
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool SetServiceStatus(IntPtr handle, ref SERVICE_STATUS status);
    delegate void MainHandler(int argc, IntPtr argv);
    delegate int ControlHandler(int code,int type,IntPtr data,IntPtr context);
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct ENTRY { public string name; public MainHandler main; }
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool StartServiceCtrlDispatcher(ENTRY[] table);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr RegisterServiceCtrlHandlerEx(string name,ControlHandler handler,IntPtr context);
    static string root;
    static IntPtr handle;
    static ManualResetEvent stopped=new ManualResetEvent(false);
    static MainHandler main=Run;
    static ControlHandler control=Control;
    // 標準の終了前通知を受けるだけで、検体やOSの関数を書き換えない。
    static void Status(int state,int accepted) {
        SERVICE_STATUS s=new SERVICE_STATUS(); s.type=16; s.state=state; s.accepted=accepted;
        if(!SetServiceStatus(handle, ref s)) throw new System.ComponentModel.Win32Exception();
    }
    static void Run(int argc,IntPtr argv) {
        handle=RegisterServiceCtrlHandlerEx("r_AKanaly_Lifecycle",control,IntPtr.Zero);
        Status(4,1|4|256); stopped.WaitOne(); Status(1,0);
    }
    static int Control(int code,int type,IntPtr data,IntPtr context) {
        try { if(code==15 || code==5) { Record(); stopped.Set(); } else if(code==1) { stopped.Set(); } }
        catch { stopped.Set(); }
        return 0;
    }
    // 終了通知は短い書込みだけに限定し、OS終了を長時間妨げない。
    static void Record() {
        string path=Path.Combine(root,"lifecycle-shutdown.json");
        string text="{\"utc\":\""+DateTime.UtcNow.ToString("o")+"\",\"kind\":\"preshutdown\"}";
        using(var f=new FileStream(path,FileMode.Create,FileAccess.Write,FileShare.Read)) {
            byte[] b=Encoding.UTF8.GetBytes(text); f.Write(b,0,b.Length); f.Flush(true);
        }
    }
    public static void Main(string[] args) { root=args[0]; StartServiceCtrlDispatcher(new ENTRY[]{new ENTRY{name="r_AKanaly_Lifecycle",main=main},new ENTRY()}); }
}
'@
$exe=Join-Path $Root 'LifecycleService.exe'
if(Get-Service r_AKanaly_Lifecycle -ErrorAction SilentlyContinue) { Stop-Service r_AKanaly_Lifecycle; & sc.exe delete r_AKanaly_Lifecycle | Out-Null; Start-Sleep -Seconds 2 }
if(Test-Path -LiteralPath $exe) { Remove-Item -LiteralPath $exe -Force }
Add-Type -TypeDefinition $serviceCode -ReferencedAssemblies System.ServiceProcess -OutputAssembly $exe -OutputType WindowsApplication
New-Service -Name r_AKanaly_Lifecycle -BinaryPathName ('"'+$exe+'" "'+$Root+'"') -StartupType Automatic | Out-Null
$options=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$system=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
$monitor=New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$Root+'\lifecycle_monitor.ps1" -Root "'+$Root+'"')
Register-ScheduledTask -TaskName r_AKanaly_LifecycleMonitor -Action $monitor -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $system -Settings $options -Force | Out-Null
$account=$env:COMPUTERNAME+'\'+$GuestUser
$user=New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Limited
# GUI操作用Agentの常駐が、解析対象の画面をコンソール窓で隠さないようにする。
$launcher=New-ScheduledTaskAction -Execute ($Root+'\agent\runtime\pythonw.exe') -Argument ('"'+$Root+'\agent\code\lifecycle_agent_launcher.py" --root "'+$Root+'"')
Register-ScheduledTask -TaskName r_AKanaly_OSAgent -Action $launcher -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $account) -Principal $user -Settings $options -Force -ErrorAction Stop | Out-Null
# ユーザーは固定タスクの起動と状態参照だけを行う。
$scheduler=New-Object -ComObject Schedule.Service
$scheduler.Connect()
foreach($name in @('r_AKanaly_LifecycleMonitor','r_AKanaly_OSAgent')) { $scheduler.GetFolder('\').GetTask($name).SetSecurityDescriptor(('D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;'+$sid+')'),0) }
& wevtutil.exe sl Microsoft-Windows-TaskScheduler/Operational /e:true
if($LASTEXITCODE -ne 0) { throw 'TaskScheduler channel enable failed' }
Start-Service r_AKanaly_Lifecycle
Start-ScheduledTask r_AKanaly_LifecycleMonitor
Start-ScheduledTask r_AKanaly_OSAgent
@{version=1;complete=$true;utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'lifecycle-installed.json') -Encoding UTF8
Stop-Transcript | Out-Null
