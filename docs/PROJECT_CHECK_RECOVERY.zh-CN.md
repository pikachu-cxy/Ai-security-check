# 旧项目升级后的自动检查恢复

旧项目不需要手动导入。全局安装后，产品根据打开的项目目录接入检查；
同一聊天已有的有效比较记录保存在产品数据目录中，升级时继续使用。
旧项目自己残留的接入配置冲突属于另一种问题，产品会单独提示，不能把
所有“准备失败”都归因于项目未导入或安装遗漏。

## 本次修复

- 重连时先读取同一项目、同一宿主、同一聊天的有效检查记录，
  避免因为其他检查占用项目锁而错误阻断。
- 已失败的准备任务发现原比较记录可用时恢复检查，后续修改继续检查。
- 缺失、损坏或属于其他项目/聊天的记录不用于恢复；
  修改后的文件不会被用来补造该次修改的“修改前”记录。
- 分别记录锁占用、超时、准备期间文件变化、文件数量或大小超限、
  代码检查未完成和访问权限等原因；未知错误保留为未知，不复制原始异常和路径。
- 提示区分未启动、准备中和部分完成；同一轮只提示一次。
  本轮检查后来完成时，以当前结果为准，不再重复旧的未启动提示。
- 普通问答、只读操作、无实际改动时不展示通用检查警告。

## 生成新版安装包

在项目的 PowerShell 中执行。脚本会检查许可证、运行回归测试，
全部通过后生成新的独立安装包并更新安装包位置记录。

```powershell
Set-Location 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check'
.\.venv\Scripts\python.exe .\scripts\rebuild_dependency_fix.py
if ($LASTEXITCODE -ne 0) { throw '测试或构建失败，请保留输出，不要继续安装' }
```

## 使用正常产品安装流程

确认上一步成功后，关闭 Codex。在独立的 PowerShell 窗口中执行：

```powershell
Set-Location 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check'
$bundleInfo = Get-Content '.\artifacts\dependency-fix-latest.json' -Raw | ConvertFrom-Json
$runtimeExe = $bundleInfo.executable
if (-not (Test-Path -LiteralPath $runtimeExe -PathType Leaf)) { throw '找不到本次生成的安装程序' }
& $runtimeExe install codex
if ($LASTEXITCODE -ne 0) { throw '安装失败，请保留输出' }
& $runtimeExe preparation watch
```

之后重新打开 Codex 和原项目。工具、漏洞数据的准备进度与项目的比较记录
是不同状态；漏洞数据过期不等于项目没导入。安装和准备命令会显示具体状态。

## 手动验收

1. 打开原项目，先进行普通问答或只读查看文件，不应出现通用检查警告。
2. 在原聊天中，让 Codex 给一个现有源码函数添加一行用途注释。
   有有效旧记录时应继续自动检查，不要求重新导入项目。
3. 如果某次检查确实不能开始，提示应写明“自动安全检查未启动”、
   已知原因、处理方式和“本次修改尚未检查”，不只说“尚未完成”。
4. 如果后续检查已完成，总结应使用新结果，不继续附带旧的失败提示。

首次准备失败且完全缺少修改前记录时，历史修改无法补造比较依据。
此时按具体错误处理后新建聊天，为后续修改建立正常的检查记录。
