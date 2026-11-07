# r_AKanaly

[日本語](README.md) | **English**

> [!IMPORTANT]
> **Please visit the official website first.**
> **[▶ Explore r_AKanaly — r-akanaly.com](https://r-akanaly.com/en/)**
> This README explains how it works and how to install and use it.

A Windows application that coordinates sample analysis and saves HTML reports and analysis results.

**Version: 0.1.5**
Please visit [GitHub Releases](https://github.com/k0011m/r_AKanaly/releases) for downloads, the scope of validation and limitations for this version.

## What is r_AKanaly?

**r_AKanaly is a Windows application that connects malware analysis tools and custom resident VM agents to Codex, taking a sample from investigation through to an HTML report.**

You select a sample and analysis settings. r_AKanaly restores the VM, transfers the sample, collects execution logs and prepares the tools. Codex uses the resulting evidence to investigate further and write a report. It does not simply submit a sample to an LLM for an answer: **Codex can request work from tools inside the VM, read their results and choose what to investigate next.**

The Host is the user's PC running r_AKanaly; the Guest is Windows inside the VM. Dynamic sample execution and Ghidra analysis take place in the Guest. The Host coordinates the workflow, stores artifacts and connects to Codex.

## Requirements

- A Windows x64 PC. This distribution does not target x86 or ARM.
- VMware Workstation and vmrun.
- A dedicated Windows x64 analysis VM (`.vmx`) with VMware Tools installed and working inside the Guest.
- Guest login credentials and the ability to approve administrator operations inside the Guest. An encrypted VM also requires its encryption password.
- An authenticated environment and account that can use Codex, with an internet connection when required.
- Internet access on the Host to download external tools during initial setup.
- Sufficient storage for the VM, snapshots and analysis results.

Windows, VMware and Codex usage rights, and a Windows VM itself, are not included. Please prepare VMware Workstation and a dedicated Windows analysis VM, then install VMware Tools inside the Guest.

If .NET Framework 3.5 is not enabled in the Guest, please attach exactly one Windows installation ISO matching the Guest Windows build to the VM's CD/DVD drive. Setup uses that media to install the required feature. Windows installation media is not included.

Setup configures Guest automatic login, power settings, analysis-specific protection settings, an isolated network and snapshots. Please use a dedicated analysis VM and shut it down before starting the installation. Do not select a VM used for everyday work.

Please select manual registry setup (recommended) or configuration and verification through official APIs after startup. Selecting manual mode in the dropdown immediately displays the instructions and baseline snapshot field. Configure the selected Guest, restart it, and confirm that `DisableAntiSpyware=1` persists and Defender is stopped. Shut down the Guest, create a snapshot, and select it using Refresh snapshot list.

Setup restores and boots that baseline and verifies the registry value and effective protection state before deploying tools or Agents. Dynamic and static environments each derive from the same newly provisioned common snapshot, rather than older analysis snapshots. A failed baseline check preserves Guest state. Resume with identical inputs to recheck without restoring again. Please use a new installation directory if you select a different baseline.

### Recommended troubleshooting when the value disappears

In **the selected Guest only**, first set `DisableAntiSpyware` under `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender` to REG_DWORD `1` and restart. If the value disappears, please try the following:

1. Create a REG_QWORD value with the same name, set it to `1`, and restart.
2. Confirm the QWORD persists, then delete that value.
3. Recreate the same name as REG_DWORD `1` and restart.
4. Confirm that the DWORD persists and effective protection is OFF, then shut down the Guest and create the baseline snapshot.

This sequence was reproduced twice in a user's analysis VM; neither success on every system nor the causal effect of the intermediate QWORD is established. Please do not perform it on the Host. The final value is REG_DWORD even on 64-bit Windows. Setup can also read existing REG_QWORD values, but verifies effective protection after restart and before analysis rather than accepting a value of 1 alone.

If protection verification fails during manual-mode setup, follow the dialog to correct the Guest settings, restart and verify Windows, then shut down the Guest. Setup does not automatically rewrite registry values for this repair. It verifies the resulting state, creates a new snapshot in the cloned VM without deleting or overwriting existing snapshots.

Successful setup registers the installation directory in the user environment variable `R_AKANALY_HOME` and user PATH. Please reopen your terminal. Settings are still selected through `current.json`; arbitrary environment variables in JSON are not automatically expanded.

### Where to make the manual change

**Change only `DisableAntiSpyware` under Policies in the selected Guest.**

1. Inside the Guest, press `Win+R`, enter `regedit`, and open Registry Editor.
2. Paste `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender` into the top address bar and press Enter.
3. Open `DisableAntiSpyware` in the right pane and set Value data to `1`. If it is absent, right-click an empty area in the right pane, choose New > DWORD (32-bit) Value, name it `DisableAntiSpyware`, and set it to `1`.

**Do not create, change, or delete the similarly named location without Policies, `DisableAntiVirus`, other values or keys, or permissions. Do not perform these steps on the Host.** If the target key is missing, check the entered path instead of substituting another location. Follow Setup instructions for restarting, verifying, and shutting down the Guest.

**In manual mode, v0.1.5 creates an independent full VM clone from the selected snapshot and provisions only that clone. The original VM and snapshots are preserved.** This also applies when selecting an existing VM. Allow disk space and time for a full copy. Do not rerun a failed v0.1.3/v0.1.4 Setup; use this version with a new installation directory. Legacy progress targeting the original VM is rejected without modifying it.

## Installation

Please download `r_AKanaly-0.1.5-installer-windows-x64.zip` from the assets on [GitHub Releases](https://github.com/k0011m/r_AKanaly/releases) and extract the entire archive into one folder. The `Source code` downloads and the update ZIP without `installer` in its name are not initial installation packages. Please keep `Setup.exe` with the accompanying files and follow these steps.

1. Open `Setup.exe` and select Japanese or English.
2. Choose the application installation directory and the results directory.
3. Check the detected VMware, vmrun and existing-tool paths. Use the browse buttons to correct them if necessary.
4. Select the VM and enter its Guest credentials. Choose whether to copy the VM or use the specified VM directly.
5. Review the settings and start setup. If Guest UAC approval is requested, please open the Guest screen in VMware, review the request and approve it there.
6. After setup completes, open `r_AKanaly.exe` in the installation directory.

Setup installs the agents and analysis tools, creates analysis snapshots and generates the JSON configuration for that VM. Once setup completes, please use the installed application to configure the sample to analyze.

Setup downloads Ghidra, Java (Temurin JDK), DiE, FLOSS, capa, ILSpy/ilspycmd and .NET to the Host from their official sources. It verifies the size and SHA-256 of each pinned version before deploying it to the Guest. For Procmon and Sysmon, please review and accept the displayed license terms. Setup then downloads and verifies them from Microsoft before deployment. The Guest does not need an internet connection for these downloads.

## Starting the application

Please open `r_AKanaly.exe` and use ↑ / ↓ and Enter to select an item.

| Menu label | Purpose |
| --- | --- |
| 実行 — Run | Confirm the target and settings, then start analysis. |
| 設定 — Settings | View the active JSON path and edit paths, the dynamic-analysis LLM toggle and instructions. |
| ヘルプ — Help | Read the operating instructions. |
| 更新 — Update | Close the analysis application and switch to the updater. |
| 終了 — Exit | Close the application. |

## Run your first analysis

1. Please open `r_AKanaly.exe` in the installation directory, select Settings and note the path displayed under 設定JSON (configuration JSON).
2. Close the application and open that JSON in a text editor such as Notepad. Choose the example below for a single ZIP, a single EXE or a batch directory, and edit the relevant values. Please retain the VM paths and snapshots generated by Setup.
3. Save the JSON, reopen the application and select Run. Please confirm the target, VM and output location before starting.
4. Once analysis completes, please open the HTML report at the location shown on screen.

**First use requires trusting the analysis folder and approving its hooks in Codex.** This is separate from completing Setup. If analysis stops with `SessionStart was not observed`, please follow these steps.

1. Open and trust the folder shown as Codex PJ (`llm.codex_project_dir` in the JSON) in Codex.
2. In the Hooks screen, review and approve `SessionStart`, `PreToolUse` and `PermissionRequest` that use that folder's `.codex/hooks/r_AKanaly_guard.exe`.
3. Rerun analysis from the beginning with the same JSON.

An `analysis_failed.html` produced while waiting for approval is not a successful analysis report. Changing the analysis folder or hook definitions may require reviewing approval again.

## Using the JSON configuration

### Please check which configuration file to edit first

**Edit the active JSON generated by Setup. Do not replace it with the example configuration: that would discard your configured VM paths and snapshots.**

The file shown under 設定JSON (configuration JSON) in Settings is the file to edit. To change the ZIP member, password, batch-mode toggle or other values not available on that screen, please close the application and open the file in a text editor such as Notepad. To locate it manually, open `current.json` in the installation directory and find the file named by `settings`. That path is relative to the installation directory. Configuration filenames differ between installations, so please use the path recorded for your own installation.

- `r_AKanaly_setting.example.json` under `versions/` is a reference file. Please edit the configuration selected by `current.json` for your analysis.
- `current.json` selects the installed version and settings file. Do not add sample settings to it.
- Keep a copy before editing and save changes before starting analysis. Edits do not immediately change an analysis already running.

The Settings screen lets you edit paths, the dynamic-analysis LLM toggle and instructions. Please press `S` to save edits made on that screen. `Q` returns without saving.

### Configuration writing rules

- Please save the file using UTF-8 encoding.
- `null` has a different meaning for different settings. In particular, it is not the same as `""` for a ZIP password.
- Use absolute paths for ordinary file locations; relative-path bases differ between settings.
- `malware_transfer.host_path` means the `host_path` key inside the `malware_transfer` object, not a new key containing a dot.

**The JSON blocks below are partial editing examples. Apply the shown values to the matching keys in your active configuration, preserving all other settings. Do not replace the entire configuration with a snippet or append duplicate objects.**

### Analyze one ZIP

```json
{
  "malware_transfer": {
    "host_path": "C:/Samples/sample.zip",
    "guest_path": "C:\\Users\\Public\\r_AKanaly\\samples\\sample.exe",
    "zip_member": "payload/sample.exe",
    "zip_password": "",
    "zip_max_uncompressed_bytes": 536870912
  },
  "full_auto": {
    "enabled": false,
    "recursive": true
  }
}
```

| Setting | Meaning |
| --- | --- |
| `host_path` | Absolute path to the ZIP file on the Host. |
| `guest_path` | Full destination **file path** for the extracted sample in the Guest, not the archive destination. Normally retain the Setup value. |
| `zip_member` | Relative path of the target inside the ZIP. **Required for single-ZIP analysis, even if the archive contains only one EXE.** Use `payload/sample.exe` for a file inside `payload`, or `sample.exe` for a file at the archive root. |
| `zip_password` | See the password table below. This is the archive password. |
| `zip_max_uncompressed_bytes` | Extraction size limit in bytes; the example is 512 MiB. Change only when needed. |
| `full_auto.enabled` | `false` for a single sample. `recursive` has no effect in this mode. |

Use the actual member name; do not supply a Host path or a path containing `../`. Inspecting the archive's file listing does not require extracting the sample on the Host. **Sample extraction takes place in the Guest.** ZIP analysis requires `static_vm.enabled: true`; keep the Setup-generated value.

| ZIP condition | `zip_password` | Behavior |
| --- | --- | --- |
| No password | `""` | No prompt; process without a password. |
| Enter at runtime | `null` | Prompt for hidden input. Pressing Enter alone means no password. |
| Known password | `"actual-password"` | Use that string. It remains plaintext in the JSON. |

The `host_path` extension determines ZIP versus direct-file input; `.ZIP` also works. No separate format setting is needed. Please use ZIP for archive input; `.7z` and `.rar` are not supported.

### Analyze one EXE directly

```json
{
  "malware_transfer": {
    "host_path": "C:/Samples/sample.exe",
    "guest_path": "C:\\Users\\Public\\r_AKanaly\\samples\\sample.exe",
    "zip_member": null,
    "zip_password": null
  },
  "full_auto": {
    "enabled": false
  }
}
```

ZIP settings are unused for an EXE, so this `zip_password: null` does not request an archive password. **Initial surface inspection of a direct EXE occurs on the Host; dynamic execution and Ghidra analysis occur in the Guest.** Use ZIP input if you want to keep only an unextracted archive on the Host.

### Analyze a folder of samples

```json
{
  "malware_transfer": {
    "host_path": "C:/Samples/batch",
    "zip_member": null,
    "zip_password": ""
  },
  "full_auto": {
    "enabled": true,
    "recursive": true
  }
}
```

- Set `host_path` to a **directory**. Its `.exe` and `.zip` files are enumerated at startup and processed sequentially.
- `recursive: true` includes subdirectories; `false` includes only the selected directory.
- Each batch ZIP must contain **exactly one EXE**. Batch mode selects it from the archive listing and overrides `zip_member`. Zero or multiple EXEs cause an input error for that ZIP.
- Batch mode does not iterate over every EXE in a ZIP. For an archive with multiple EXEs, use single-sample mode with an explicit `zip_member`.
- The ZIP password is shared throughout a batch, including a value entered when the setting is `null`. Run archives with different passwords separately.
- Individual failures are recorded and processing normally continues. Cancellation, problems before execution approval, or an unrecoverable VM can stop the batch.

### Change the results directory

**Final reports and intermediate data have separate destinations. To move both, change both settings:**

```json
{
  "llm": {
    "analysis_output_dir": "D:/AnalysisResults"
  },
  "output_directories": {
    "use_common_output_dir": true,
    "common_output_dir": "D:/AnalysisResults"
  }
}
```

- `llm.analysis_output_dir` is the parent directory for final reports and metadata.
- `output_directories.common_output_dir` is the common destination for intermediate surface, static and dynamic analysis data. Changing it alone does not move final reports.
- With `use_common_output_dir: false`, supply all three keys in that object: `surface_analysis_output_dir`, `static_analysis_output_dir` and `dynamic_analysis_output_dir`. Keep `llm.analysis_output_dir` separately configured.
- Results are separated per sample. Use different directories for sample inputs and results.

### Enable Codex-assisted dynamic analysis and set instructions

```json
{
  "dynamic_analysis": {
    "execution_timeout_seconds": 300,
    "post_exit_seconds": 10,
    "llm_control": {
      "enabled": true,
      "prompt": "Inspect the program's visible UI and generated files. Distinguish observed behavior from unverified possibilities.",
      "instruction_file": null,
      "max_duration_seconds": 900
    }
  }
}
```

| Setting | Effect |
| --- | --- |
| `dynamic_analysis.llm_control.enabled` | `true` enables Codex-driven dynamic investigation; `false` uses normal sample execution and logging. **Static analysis and report generation still use Codex when this is false.** |
| `prompt` | Dynamic investigation instructions. Write line breaks as `\n` within a JSON string. |
| `instruction_file` | UTF-8 instruction file read when `prompt` is `null`. Relative paths are based on the **active configuration file's directory**. |
| `max_duration_seconds` | Time budget for LLM-driven dynamic control, in seconds. |
| `execution_timeout_seconds` | Normal sample-execution wait limit, in seconds; not a timeout for the whole analysis. |
| `post_exit_seconds` | Additional observation after sample exit, in seconds. |

To request a specific investigation, please write instructions in `prompt` before running. To read instructions from a file, please set `prompt` to `null` and specify `instruction_file`.

With `prompt: ""`, the default instructions are used and `instruction_file` is not read. Empty instructions, a missing instruction file or instructions that do not pass the LLM instruction check also fall back to defaults. If your instructions were not applied, please check the recorded reason.

Do not confuse investigation duration with `finalize_timeout_seconds`, `transfer_timeout_seconds` or `conversion_timeout_seconds`, which control collection finalization, transfer and Host conversion waits. Specify the durations above as positive integers.

### Save periodic screenshots

```json
{
  "dynamic_analysis": {
    "llm_control": {
      "screenshot_recording_enabled": true,
      "screenshot_interval_seconds": 10,
      "screenshot_output_dir": "{analysis_dir}/dynamic_screenshots"
    }
  }
}
```

This example records the dynamic-analysis screen every 10 seconds. `{analysis_dir}` is replaced with that sample's result directory. These images are for later user review, separately from images automatically sent to Codex. Periodic recording works even with `llm_control.enabled: false`.

### Settings normally retained from Setup

| Setting | Role |
| --- | --- |
| `vmware.vmrun_path` / `vmware.vmx_path` | Host vmrun executable and target VM. |
| `vmware.snapshot_name` | Snapshot restored before dynamic analysis. |
| `static_vm.snapshot_name` | Surface/static-analysis snapshot, separate from the dynamic one. |
| `static_vm.guest_root` / `static_vm.guest_python` | Guest agent and Python locations. |
| `static_vm.security_strategy` / `dynamic_analysis.require_defender_disabled` | Match the preparation/checking method established by Setup. |
| `dynamic_analysis.guest_root` / `dynamic_analysis.task_name` / `dynamic_analysis.sample_task_name` | Guest logging directories and registered tasks. |
| `dynamic_analysis.host_procmon_path` | Host log-conversion executable acquired and verified by Setup. |
| `guest.username` / `credentials.env_file_path` | Guest connection settings. Installed credentials are stored using DPAPI; `env_file_path` is normally `null`. Do not put a VM password in the ZIP password field. |
| `llm.codex_project_dir` | Codex's analysis workspace, not the report destination. Changing it may require reviewing Hook approval for the new workspace. |
| `codex_malware_guard` | Host operation restrictions; not a setting to change when switching samples. |

Other useful settings are `llm.language` for report language, `llm.model` / `llm.reasoning_effort` for model and reasoning configuration, and `static_analysis.yara_rule_path` for optional YARA rules. Model availability depends on your Codex environment. Keep `llm.report_format` set to `"html"` for normal 0.1.5 operation.

### Please save and check the configuration before running

1. Save the edited active JSON.
2. Open PowerShell in the installation directory and check the configuration:

```powershell
.\r_AKanaly.exe --dry-run
```

To check a separate configuration copy, save the file first, then specify it explicitly. This affects only that launch; it does not change `current.json` for normal launches.

```powershell
.\r_AKanaly.exe --settings ".\config\my-analysis.json" --dry-run
```

3. Before Run, review the single/batch mode, sample, archive member, target VM and results directory in the execution confirmation. Dynamic analysis executes the sample inside the Guest.

`--dry-run` performs preliminary configuration checks; it does not guarantee Guest connectivity, archive decryption/extraction, tool execution or successful analysis. Unknown-key handling differs between configuration blocks, so spelling mistakes are not guaranteed to produce an error. Use the exact key names.

## Results

Please open the location shown at completion. If the results are in a ZIP, please extract it and open the HTML report in a browser. Report-generation status and individual stage results are shown separately. A successfully generated HTML report does not mean that every behavior of the sample was observed.

After a normal HTML report is saved inside the result directory, results are archived into a password-free ZIP. The archive contents are hash-verified before the original result directory is removed. Batch mode does this for each sample. Automatic ZIP archiving cannot be disabled through the JSON settings. If the report is missing or archiving/verification fails, check the displayed status and remaining logs rather than assuming a normal completion ZIP was produced.

## Updates

Please select Update from the main menu. The application closes and opens the updater, which displays the installed and available versions. Downloading, verification and installation proceed only after you select the option to update. Press Enter on the result screen to return to the application.

The update source is `k0011m/r_AKanaly`. Updates are checked against the production Ed25519 public key. Missing releases, network errors and verification failures do not activate an update.

## Troubleshooting

- Record the stage, error and result location shown when startup or analysis fails.
- Check the VM path, login credentials and VMware Tools.
- Record the updater's error if an update fails.
- Include your application version and reproduction steps when reporting an issue. Do not attach passwords, credentials or samples themselves.

## What do the custom agents do?

An agent here is a program that waits inside the VM for commands. These agents are not additional LLMs. They connect Codex, which decides what to investigate, with the tools that carry out the work.

- **Guest OS Agent:** provides operations such as process and window inspection, application launch, ZIP extraction, screenshots and UI interaction. When Codex-assisted dynamic analysis is enabled, Codex can use the exposed operations to investigate inside the VM.
- **Ghidra analysis Agent:** keeps Ghidra running inside the VM and accepts queries about the analyzed program. It returns function lists, decompiled code and call relationships, allowing Codex to inspect specific areas repeatedly.
- **Host bridge:** delivers Codex's requests to the VM and returns the agents' results. MCP, a protocol for exposing external tools to an LLM, provides the tool interface. VMware Guest Operations carries requests and results between the Host and VM.

For example, Codex might decide to investigate when a function overwrites a file. It requests that function's decompiled code; the bridge delivers the request and the Ghidra analysis Agent returns the result. Codex can then inspect the callers or compare the code with file writes recorded during execution.

```text
User: selects a sample and analysis conditions
  ↓
r_AKanaly: coordinates VM restoration, preparation, transfer and logging
  ↓
Codex: chooses what to investigate
  ⇅ MCP / Host bridge / VMware Guest Operations
Custom agents inside the VM: execute requests and return results
  ⇅
Analysis tools such as Ghidra, and the Guest OS
  ↓
Codex: compares tool results with execution logs and writes the report
```

## Analysis workflow

1. **Inspect basic file information.** Select an EXE or ZIP. ZIP samples are extracted and inspected inside the Guest. Initial inspection of a directly supplied EXE takes place on the Host.
2. **Prepare the dynamic-analysis VM.** Restore its snapshot and check the agents and loggers before placing the sample in the Guest.
3. **Execute and observe.** Sysmon, Process Monitor and ETW record activity such as process launches, file operations and registry changes. Codex-assisted dynamic operation can be enabled or disabled.
4. **Collect original logs.** Transfer them to the Host, verify their hashes and convert them into readable data.
5. **Perform static analysis and follow-up investigation.** Switch to the static-analysis snapshot. Codex operates Ghidra and other tools through the custom agents, comparing code with the behavior observed during execution.
6. **Save the HTML report and artifacts.** Record findings, supporting evidence and unresolved questions. Individual stage failures are recorded separately.

Code may describe behavior that was not observed during execution. r_AKanaly uses both sources of evidence, but cannot guarantee that every behavior will be observed. Review the report together with its execution conditions and observation limits.

## License and third-party software

**Noncommercial use, modification and redistribution are free. Commercial use requires prior written permission for both original and modified versions.** Paid services and internal business use supporting for-profit activities count as commercial use. Modified source need not be published. Redistribution must retain copyright and license notices and identify modifications.

Full terms: [r_AKanaly Noncommercial License 1.0](LICENSE.en.md) ([controlling Japanese text](LICENSE.md)). Commercial permission: [rk01mwork@gmail.com](mailto:rk01mwork@gmail.com). Scope and any fees are agreed separately.

Bundled and integrated third-party software retains its own licenses. Please see the [third-party software notices](THIRD_PARTY_NOTICES.md).

Ghidra, Java, DiE, FLOSS, capa, ILSpy/ilspycmd, .NET, Procmon and Sysmon are not bundled; Setup downloads them from their official sources. Runtime libraries needed by the application and its agents, such as Python, remain bundled. Initial setup requires internet access on the Host. If a downloaded package does not match its pinned size or hash, Setup stops deployment. Please check the displayed error and use updated Setup/distribution assets.

