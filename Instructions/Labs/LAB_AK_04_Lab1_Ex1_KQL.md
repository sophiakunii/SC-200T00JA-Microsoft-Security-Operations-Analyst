# モジュール 4 - ラボ 1 - 演習 1 - Kustoクエリ言語 (KQL) を使用した Azure Sentinel 用のクエリの作成

## ラボ シナリオ
あなたは、Azure Sentinel を実装しようとしている会社で働いているセキュリティ オペレーションアナリストです。悪意のあるアクティビティを検索し、視覚化を表示し、脅威ハンティングを実行するためにログ データ分析を行う責任があります。ログ データのクエリには、Kusto クエリ言語 (KQL) を使用します。

### タスク 1: KQL テストエリアにアクセスします。

このタスクでは、KQLステートメントの記述を練習できる Log Analytics 環境にアクセスします。

1. 管理者として WIN1 仮想マシンにログインします。パスワードは **Pa55w.rd**。  

2. ブラウザーで https://aka.ms/lademo にアクセスします。MOD 管理者の資格情報を使用してログインします。 

3. 画面左側のタブのリストから使用可能なテーブルを調べます。

4. クエリエディタで、次のクエリを入力し、実行 ボタンを選択します。  下部のウィンドウにクエリ結果が表示されます。

```KQL
SecurityEvent
```

5. 最初のレコードの横にある「**>**」を選択して、行の情報を展開します。

### タスク 2: 基本的な KQL ステートメントを実行する

このタスクでは 基本的な KQL ステートメントを作成します。

**注:**  各手順で、クエリ ウィンドウから前のステートメントをクリアするか、最後に開いたタブ (最大 25) の後の「**+** 」を選択して新しいクエリ ウィンドウを開きます。

1. 次のステートメントは、let ステートメントを使用して変数をデモンストレーションする方法を示しています。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 


```KQL
let timeOffset = 7d;
let discardEventId = 4688;
SecurityEvent
| where TimeGenerated > ago(timeOffset*2) and TimeGenerated < ago(timeOffset)
| where EventID != discardEventId
```

2. 次のステートメントは、let ステートメントを使用して動的リストを宣言する方法を示しています。クエリウィンドウで、次のステートメントを入力し、「**実行**」を選択します。 


```KQL
let suspiciousAccounts = datatable(account: string) [
    @"\administrator", 
    @"NT AUTHORITY\SYSTEM"
];
SecurityEvent | where Account in (suspiciousAccounts)
```

3. 次のステートメントは、「let」 ステートメントを使用して動的リストを宣言する方法を示しています。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 

```KQL
let LowActivityAccounts =
    SecurityEvent 
    | summarize cnt = count() by Account 
    | where cnt < 10;
LowActivityAccounts | where Account contains "Mal"
```

**注:** このスクリプトを実行しても、結果は得られません。

4. 次のステートメントは、クエリウィンドウに表示されるクエリ時間範囲内のレコードをすべてのテーブルと列で検索する方法を示しています。このスクリプトを実行する前に、クエリウィンドウで、「**時間範囲**」を「最後の時間」に変更します。次のステートメントを入力し、「**実行**」を選択します。 

```KQL
search "err"
```

**警告:** 次のスクリプトのために、必ず時間範囲を「過去 24 時間」に戻してください。

5. 次のステートメントは、「in」句でリストされたテーブル全体で、クエリウィンドウに表示されるクエリ時間範囲内のレコードを検索する方法を示しています。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 

```KQL
search in (SecurityEvent,SecurityAlert,A*) "err"
```


6. 次のステートメントは、where 演算子を使用したフィルターを示しています。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 

**注:** 以下の各コードブロックからクエリを入力した後、「実行」する必要があります。

```KQL
SecurityEvent
| where TimeGenerated > ago(1d)
```

```KQL
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == "4624"
```

```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| where AccountType =~ "user"
```

```KQL
SecurityEvent | where EventID in (4624, 4625)
```


7. 次のステートメントは、クエリウィンドウで extend 演算子を使用してフィールドを作成する方法を示しています。次のステートメントを入力し、「**実行**」を選択します: 


```KQL
SecurityAlert
| where TimeGenerated > ago(7d)
| extend severityOrder = case (
    AlertSeverity == "High", 3,
    AlertSeverity == "Medium", 2, 
    AlertSeverity == "Low", 1,
    AlertSeverity == "Informational", 0,
    -1)
```


8. 次のステートメントは、let、ダイナミクスリストの作成、およびextendを使用したフィールドの作成を組み合わせた実際の例を示しています。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 

```KQL
let timeframe = 1d;
let DomainList = dynamic(["tor2web.org", "tor2web.com"]);
Syslog
| where TimeGenerated >= ago(timeframe)
| where ProcessName contains "squid"
| extend 
  HTTP_Status_Code = extract("(TCP_(([A-Z]+)…-9]{3}))",8,SyslogMessage),    
  Domain = extract("(([A-Z]+ [a-z]{4…Z]+ )([^ :\\/]*))",3,SyslogMessage)
| where HTTP_Status_Code == "200"
| where Domain contains "."
| where Domain has_any (DomainList)
```

**注:** このスクリプトを実行しても、結果は得られません。

9. 次のステートメントは、order by 演算子を使用した結果の並べ替えを示しています。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 


```KQL
SecurityAlert
| where TimeGenerated > ago(7d)
| extend severityOrder = case (
    AlertSeverity == "High", 3,
    AlertSeverity == "Medium", 2, 
    AlertSeverity == "Low", 1,
    AlertSeverity == "Informational", 0,
    -1)
| order by severityOrder desc
```

10. 次のステートメントは、プロジェクト演算子を使用して結果セットのフィールドを指定する方法を示しています。

**注:** 以下の各コードブロックからクエリを入力した後、「実行」する必要があります。

クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 


```KQL
SecurityEvent
| project Computer, Account
```



```KQL
SecurityAlert
| where TimeGenerated > ago(7d)
| extend severityOrder = case (
    AlertSeverity == "High", 3,
    AlertSeverity == "Medium", 2, 
    AlertSeverity == "Low", 1,
    AlertSeverity == "Informational", 0,
    -1)
| order by severityOrder
| project-away severityOrder
```

### タスク 3: Summarize 演算子を使用してKQLで結果を分析する

このタスクでは、データを準備するためのKQLステートメントを作成します

1. 次のステートメントは、count 関数を示しています。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 



```KQL
SecurityEvent
| where EventID == "4688"
| summarize count() by Process, Computer
```


2. 次のステートメントは、count 関数を示しています。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 


```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| summarize cnt=count() by AccountType, Computer
```



3. 次のステートメントは、dcount 関数を示しています。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 


```KQL
SecurityEvent
| summarize dcount(IpAddress)
```

4. 次のステートメントは、パスワード スプレーの試行を検出するための Azure Sentinel 分析ルールです。

最初の 3 つの 「where」 演算子では、結果セットをフィルター処理し、無効なアカウントへの失敗したログインを検出します。  次に、"summarize" ステートメントでアプリケーション名の個別のカウントを集計し、User と IP Address でグループ化します。  最後に、数が許容量を超えているかどうかを確認するために、作成された変数 (threshold) に対して確認が行われます。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 


```KQL
let timeframe = 1d;
let threshold = 3;
SigninLogs
| where TimeGenerated >= ago(timeframe)
| where ResultType == "50057"
| where ResultDescription =~ "User account is disabled. The account has been disabled by an administrator."
| summarize applicationCount = dcount(AppDisplayName) by UserPrincipalName, IPAddress
| where applicationCount >= threshold
```

**注:** このスクリプトを実行しても、結果は得られません。

5. 次のステートメントは、arg_max 関数を示しています。

次のステートメントはSQL12.NA.contosohotels.com コンピューターの SecurityEvent テーブルから最新の行を返します。  arg_max 関数の*でその行のすべての列を要求します。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 


```KQL
SecurityEvent 
| where Computer == "SQL12.na.contosohotels.com"
| summarize arg_max(TimeGenerated,*) by Computer
```

6. 次のステートメントは、arg_min 関数を示しています。

このステートメントでは、SQL12.NA.contosohotels.com コンピューターの最も古い SecurityEvent を結果セットとして返します。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 


```KQL
SecurityEvent 
| where Computer == "SQL12.na.contosohotels.com"
| summarize arg_min(TimeGenerated,*) by Computer
```

7. 次のステートメントは、パイプの順序に基づいて結果を理解することの重要性を示しています。「|」クエリ ウィンドウ内次のクエリを入力し、それぞれを個別に実行します。 

**Query 1** には、最後のアクティビティがログインだった Account が含まれます。まず、SecurityEvent テーブルが集計され、各 Account の最新行を返します。  その後、EventID が 4624 (ログイン) に等しい行だけ返します。

```KQL
SecurityEvent
| summarize arg_max(TimeGenerated, *) by Account
| where EventID == "4624"
```

**Query 2** には、ログインしたアカウントの最新のログインが含まれます。 SecurityEvent テーブルは、EventID = 4624 のみを含むようにフィルター処理されます。これらの結果は、Account ごとに最新のログイン行に対して集計されます。

```KQL
SecurityEvent
| where EventID == "4624"
| summarize arg_max(TimeGenerated, *) by Account
```

**注:**  「完了」を選択して、「合計 CPU」と「処理されたクエリに使用されたデータ」を確認することもできます。 バーを開き、両方のステートメント間のデータを比較します。

8. 次のステートメントは、make_list 関数を示しています。

make_list 関数では、グループ内の式のすべての値の動的な (JSON) 配列を返します。この KQL クエリでは、まず where 演算子を使用して EventID をフィルター処理します。  次に、各コンピューターについて、結果がアカウントの JSON 配列になります。結果として得られる JSON 配列には、重複するアカウントが含まれます。

クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 

```KQL
SecurityEvent
| where EventID == "4624"
| summarize make_list(Account) by Computer
```

9. 次のステートメントは、make_set 関数を示しています。

make_set　関数は、Expression がグループ内で取る*個別の*値を含む動的 （JSON） 配列を返します。この KQL クエリでは、まず where 演算子を使用して EventID をフィルター処理します。  次に、各 Computer について、結果が一意の Account の JSON 配列になります。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します。 


```KQL
SecurityEvent
| where EventID == "4624"
| summarize make_set(Account) by Computer
```

### タスク 4: レンダー演算子を使用して KQL でビジュアライゼーションを作成します

このタスクでは、KQL ステートメントを使用した視覚化の生成を使用します

1. 次のステートメントは、棒グラフを使用して結果を視覚化するレンダリング関数を示しています。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 

```KQL
SecurityEvent 
| summarize count() by Account
| render barchart
```

2. 次のステートメントは、時系列で結果を視覚化するレンダリング関数を示しています。

bin() 関数では、指定のビン サイズの整数の倍数になるように値を切り捨てます。  summarize by ... と組み合わせてよく使用されます。値のセットが分散している場合、その値は特定の値の小さなセットにグループ化されます。  生成された時系列と render 演算子へのパイプを timechart の種類と結合することで、時系列を視覚化できます。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 

```KQL
SecurityEvent 
| summarize count() by bin(TimeGenerated, 1h) 
| render timechart
```

### タスク 5: KQL でマルチテーブルステートメントを作成する

このタスクでは、マルチテーブル KQL ステートメントを作成します。

1. 次のステートメントは、2つ以上のテーブルを取得し、それらすべての行を返すunion演算子を示しています。結果を渡す方法、およびパイプ文字によってどのような影響があるかを理解することは重要です。クエリ ウィンドウ内次のステートメントを入力し、それぞれに対し**実行** を選択して、結果を確認します。 


**Query 1** で SecurityEvent のすべての行と SecurityAlert のすべての行が返されます
```KQL
SecurityEvent 
| union SecurityAlert  
```

**Query 2** で SecurityEvent のすべての行数と SecurityAlert のすべての行数である 1 つの行と列が返されます
```KQL
SecurityEvent 
| union SecurityAlert  
| summarize count() 
| project count_
```

**Query 3** で SecurityEvent のすべての行と SecurityAlert のすべての 1 つの行が返されます  SecurityAlert の行は、SecurityAlert の行数です。
```KQL
SecurityEvent 
| union (SecurityAlert  | summarize count()) 
| project count_
```

2. 次のステートメントは、複数のテーブルを結合するためのワイルドカードの union 演算子のサポートを示しています。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 


```KQL
union Security* 
| summarize count() by Type
```


3. 次のステートメントは、各テーブルから指定された列の値を照合することにより、2つのテーブルの行をマージして新しいテーブルを形成する union 演算子を示しています。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 


```KQL
SecurityEvent 
| where EventID == "4624" 
| summarize LogOnCount=count() by EventID, Account 
| project LogOnCount, Account 
| join kind = inner (
     SecurityEvent 
     | where EventID == "4634" 
     | summarize LogOffCount=count() by EventID, Account 
     | project LogOffCount, Account 
) on Account
```

結合で指定した最初のテーブルが左テーブルと見なされます。  join キーワードの後のテーブルが右テーブルです。  テーブルの列を操作する場合、$ left.Columnnameと$ right.Column nameは、参照されるテーブルの列を区別するためのものです。 

### タスク 6: KQL で文字列データを操作する

このタスクでは、KQL ステートメントを使用して構造化および非構造化文字列フィールドを操作します。

1. 次のステートメントは、extract 関数を示しています。  extract では、テキスト文字列から正規表現との一致を抽出します。抽出されたサブ文字列を指定された型に変換するオプションがあります。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 

```KQL
print extract("x=([0-9.]+)", 1, "hello x=45.6|wo") == "45.6"
```

2. 次のステートメントでは、extract 関数を使用して、SecurityEvent テーブルの Account フィールドから Account Name を取得します。クエリ ウィンドウ内次のステートメントを入力し、「**実行**」を選択します: 


```KQL
let top5 = SecurityEvent
| where EventID == 4625 and AccountType == 'User'
| extend Account_Name = extract(@"^(.*\\)?([^@]*)(@.*)?$", 2, tolower(Account))
| summarize Attempts = count() by Account_Name
| where Account_Name != ""
| top 5 by Attempts 
| summarize make_list(Account_Name);

SecurityEvent
| where EventID == 4625 and AccountType == 'User'
| extend Name = extract(@"^(.*\\)?([^@]*)(@.*)?$", 2, tolower(Account))
| extend Account_Name = iff(Name in (top5), Name, "Other")
| where Account_Name != ""
| summarize Attempts = count() by Account_Name
```

**注:** このスクリプトはスペースで区切られています。クエリ ウィンドウで 「実行」 をクリックする前に、スクリプト全体が選択されていることを確認してください。

3. 次のステートメントは、parse 関数を示しています。parse 文字列式が評価され、その値が 1 つまたは複数の計算列に解析されます。解析に失敗した文字列の計算列には null が含まれます。

次のステートメントを確認だけして、**実行しないでください**。 

```KQL
let SQlData = Event
| where Source has "MSSQL"
;
let Sqlactivity = SQlData
| where RenderedDescription !has "LGIS" and RenderedDescription !has "LGIF"
| parse RenderedDescription with * "action_id:" Action:string 
                                    " " * 
| parse RenderedDescription with * "client_ip:" ClientIP:string
" permission" * 
| parse RenderedDescription with * "session_server_principal_name:" CurrentUser:string
" " * 
| parse RenderedDescription with * "database_name:" DatabaseName:string
"schema_name:" Temp:string
"object_name:" ObjectName:string
"statement:" Statement:string
"." *
;
let FailedLogon = SQlData
| where EventLevelName has "error"
| where RenderedDescription startswith "Login"
| parse kind=regex RenderedDescription with "Login" LogonResult:string
                                            "for user '" CurrentUser:string 
                                            "'. Reason:" Reason:string 
                                            "provided" *
| parse kind=regex RenderedDescription with * "CLIENT" * ":" ClientIP:string 
                                            "]" *
;
let dbfailedLogon = SQlData
| where RenderedDescription has " Failed to open the explicitly specified database" 
| parse kind=regex RenderedDescription with "Login" LogonResult:string
                                            "for user '" CurrentUser:string 
                                            "'. Reason:" Reason:string 
                                            " '" DatabaseName:string
                                            "'" *
| parse kind=regex RenderedDescription with * "CLIENT" * ":" ClientIP:string 
                                            "]" *
;
let successLogon = SQlData
| where RenderedDescription has "LGIS"
| parse RenderedDescription with * "action_id:" Action:string 
                                    " " LogonResult:string 
                                    ":" Temp2:string
                                    "session_server_principal_name:" CurrentUser:string
                                    " " *
| parse RenderedDescription with * "client_ip:" ClientIP:string 
                                    " " *
;
(union isfuzzy=true
Sqlactivity, FailedLogon, dbfailedLogon, successLogon )
| project TimeGenerated, Computer, EventID, Action, ClientIP, LogonResult, CurrentUser, Reason, DatabaseName, ObjectName, Statement
```

4. 次のステートメントは、動的フィールドの操作を示しています

Log Analytics テーブル内には、動的タイプとして定義されたフィールドがあります。  動的フィールドには、次のようなキーと値のペアが含まれます。
{"eventCategory":"Autoscale","eventName":"GetOperationStatusResult","operationId":"xxxxxxxx-6a53-4aed-bab4-575642a10226","eventProperties":"{\"OldInstancesCount\":6,\"NewInstancesCount\":5}","eventDataId":" xxxxxxxx -efe3-43c2-8c86-cd84f70039d3","eventSubmissionTimestamp":"2020-11-30T04:06:17.0503722Z","resource":"ch-appfevmss-pri","resourceGroup":"CH-RETAILRG-PRI","resourceProviderValue":"MICROSOFT.COMPUTE","subscriptionId":" xxxxxxxx -7fde-4caf-8629-41dc15e3b352","activityStatusValue":"Succeeded"}

動的フィールド内の文字列にアクセスするには、**ドット表記**を使用します。  AzureActivity テーブルの Properties_d フィールドの型は動的です。この例では、Properties_d.eventCategory というフィールド名を使用して eventCategory にアクセスできます。

クエリ ウィンドウ内次のステートメントを入力し、**実行** 

```KQL
AzureActivity
| project Properties_d.eventCategory
```

**注:** このスクリプトを実行しても、結果は得られません。

次のステートメントを確認だけして、**実行しないでください**。 

```KQL
SigninLogs 
| where TimeGenerated >= ago(1d)
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend ConditionalAccessPol0Name = tostring(ConditionalAccessPolicies[0].displayName), ConditionalAccessPol0Result = tostring(ConditionalAccessPolicies[0].result)
| extend ConditionalAccessPol1Name = tostring(ConditionalAccessPolicies[1].displayName), ConditionalAccessPol1Result = tostring(ConditionalAccessPolicies[1].result)
| extend ConditionalAccessPol2Name = tostring(ConditionalAccessPolicies[2].displayName), ConditionalAccessPol2Result = tostring(ConditionalAccessPolicies[2].result)
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city)
| extend Date = startofday(TimeGenerated), Hour = datetime_part("Hour", TimeGenerated)
| summarize count() by Date, Identity, UserDisplayName, UserPrincipalName, IPAddress, ResultType, ResultDescription, StatusCode, StatusDetails, ConditionalAccessPol0Name, ConditionalAccessPol0Result, ConditionalAccessPol1Name, ConditionalAccessPol1Result, ConditionalAccessPol2Name, ConditionalAccessPol2Result, Location, State, City
| sort by Date
```

5. 次のステートメントは、文字列フィールドに格納されている JSON を操作する関数を示しています。多くのログでは JSON 形式でデータを送信します。そのため、JSON データをクエリ可能なフィールドに変換する方法を知る必要があります。 

クエリ ウィンドウ内次のステートメントをそれぞれ入力し、**実行** を選択します: 

```KQL
SecurityAlert
| extend ExtendedProperties = todynamic(ExtendedProperties) 
| extend ActionTaken = ExtendedProperties.ActionTaken
| extend AttackerIP = ExtendedProperties["Attacker IP"]
```


```KQL
SecurityAlert
| mv-expand entity = todynamic(Entities)
```


```KQL
SecurityAlert
| where TimeGenerated >= ago(7d)
| mv-apply entity = todynamic(Entities) on 
( where entity.Type == "account" | extend account = strcat (entity.NTDomain, "\\", entity.Name))
```

6. パーサーは、Syslog データなど、非構造化文字列フィールドが既に解析されている仮想テーブルを定義する関数です。次に示すのは、メールボックス転送の監視用にコミュニティによって作成された KQL クエリです。  

次のステートメントを確認だけして、**実行しないでください**。 

```KQL
OfficeActivity
    | where TimeGenerated >= ago(30d)
    | where Operation == 'New-InboxRule'
    | extend details = parse_json(Parameters)
    | where details contains 'ForwardTo' or details contains 'RedirectTo'
    | extend ForwardTo = iif(details[0].Name contains 'ForwardTo', details[0].Value,
        iif(details[1].Name contains 'ForwardTo', details[1].Value, 
            iif(details[2].Name contains 'ForwardTo', details[2].Value,  
                iif(details[3].Name contains 'ForwardTo', details[3].Value, 
                    iif(details[4].Name contains 'ForwardTo', details[4].Value,
                        'Check Parameters')))))
    | extend RedirectTo = iif(details[0].Name contains 'RedirectTo', details[0].Value,
        iif(details[1].Name contains 'RedirectTo', details[1].Value,
            iif(details[2].Name contains 'RedirectTo', details[2].Value,
                iif(details[3].Name contains 'RedirectTo', details[3].Value,
                    iif(details[4].Name contains 'RedirectTo', details[4].Value,
                        'Check Parameters')))))
    | extend RuleName = iif(details[3].Name contains 'Name', details[3].Value,
         iif(details[4].Name contains 'Name', details[4].Value,
            iif(details[5].Name contains 'Name', details[5].Value,
                'Check Parameters')))
    | extend RuleParameters = iif(details[2].Name != 'ForwardTo' and  details[2].Name != 'RedirectTo', 
        strcat(tostring(details[2].Name), '-', tostring(details[2].Value)),
        iif(details[3].Name != 'ForwardTo' and  details[3].Name != 'RedirectTo' and details[3].Name != 'Name',
            strcat(tostring(details[3].Name), '-', tostring(details[3].Value)), 
                iff(details[4].Name != 'ForwardTo' and details[4].Name != 'RedirectTo' and details[4].Name != 'Name' and details[4].Name != 'StopProcessingRules',
                strcat(tostring(details[4].Name), '-', tostring(details[4].Value)),
                'All Mail')))
    | project TimeGenerated, Operation, RuleName, RuleParameters, iif(details contains 'ForwardTo', ForwardTo, RedirectTo), ClientIP, UserId
    | project-rename Email_Forwarded_To = Column1, Creating_User = UserId
```

関数を作成するには：

**注:** このラボのデータに使用されるラデモ環境ではこれを行うことはできませんが、これは、環境で使用する重要な概念です。 

クエリを実行した後、「**保存**」 ボタンを選択し、名前を入力します。MailboxForwardをクリックし、ドロップダウンから 「**関数として保存**」 を選択します。   

この関数は、関数エイリアスを使用して KQL で使用できます。

```KQL
MailboxForward
```

## これでラボは終了です。

