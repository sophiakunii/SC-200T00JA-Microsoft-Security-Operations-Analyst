# モジュール 7 - ラボ 1 - 演習 5 - 攻撃を実施する

### タスク 1: Defender for Endpoint にほって保護された Windows を攻撃する

1. WIN1 にログインしてください。

2. コマンドプロンプトを管理者モードで起動します。

3. 以下のコマンドを実行します。

```Command
cd \
mkdir temp
cd temp
```

4. 攻撃 1 - レジストリキーの追加による永続性。

以下のコマンドを実行します。

```Command
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SOC Test" /t REG_SZ /F /D "C:\temp\startup.bat"
```

5. 攻撃 2  - ドメインネームサービス / コマンド＆コントロール 

この攻撃は、コマンド＆コントロール （C2） 通信をシミュレートします。

Notepad.exe を起動し、以下のスクリプトを貼り付けて **c:\temp\c2.ps1** というファイル名で保存してください。拡張子に .txt が付かないようにしてください。

```PowerShell


param(
    [string]$Domain = "microsoft.com",
    [string]$Subdomain = "subdomain",
    [string]$Sub2domain = "sub2domain",
    [string]$Sub3domain = "sub3domain",
    [string]$QueryType = "TXT",
        [int]$C2Interval = 8,
        [int]$C2Jitter = 20,
        [int]$RunTime = 240
)


$RunStart = Get-Date
$RunEnd = $RunStart.addminutes($RunTime)

$x2 = 1
$x3 = 1 
Do {
    $TimeNow = Get-Date
    Resolve-DnsName -type $QueryType $Subdomain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout

    if ($x2 -eq 3 )
    {
        Resolve-DnsName -type $QueryType $Sub2domain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout
        
        $x2 = 1

    }
    else
    {
        $x2 = $x2 + 1
    }
    
    if ($x3 -eq 7 )
    {

        Resolve-DnsName -type $QueryType $Sub3domain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout

        $x3 = 1
        
    }
    else
    {
        $x3 = $x3 + 1
    }


    $Jitter = ((Get-Random -Minimum -$C2Jitter -Maximum $C2Jitter) / 100 + 1) +$C2Interval
    Start-Sleep -Seconds $Jitter
}
Until ($TimeNow -ge $RunEnd)
```

以下のコマンドを実行してください。   

```Command
powershell
.\c2.ps1
```

**Note**: 多くの名前解決エラーが表示されるはずです。これは期待通りの動作です。コマンドプロンプトは閉じずに、このままにしておいてください。このコマンドを、何時間か実行してログ・エントリを生成する必要があります。このスクリプトの実行中に、次のタスクや次の演習に進むことができます。このタスクで作成したデータは、後でThreat Huntingラボで使用します。このプロセスでは、相当量のデータや処理を作成することはありません。

### タスク 2: Sysmon が構成された Windows を攻撃する

1. WIN2 にログインしてください。

2. コマンドプロンプトを管理者で起動します。

3. 以下のコマンドを実行します。

```Command
cd \
mkdir temp
cd temp
```

4. 攻撃 1

以下のコマンドをコマンドプロンプトで実行してください。

```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SOC Test" /t REG_SZ /F /D "C:\temp\startup.bat"
```

5. 攻撃 2

以下のコマンドをコマンドプロンプトで実行してください。

```
net user theusernametoadd /add
net user theusernametoadd ThePassword1!
net localgroup administrators theusernametoadd /add
```

# 演習 6 に進みます。
