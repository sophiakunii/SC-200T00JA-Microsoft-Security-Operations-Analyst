# モジュール 7 - ラボ 1 - 演習 6 - 検出を作成する

### タスク 1: Sysmon による攻撃 1 の検出

このタスクでは、セキュリティ イベント コネクタと Sysmon がインストールされているホストで**攻撃 1** の検出を作成します。

1. 管理者として WIN1 仮想マシンにログインします。パスワードは**Pa55w.rd** です。  

2. Microsoft Edge ブラウザーで Azure portal (https://portal.azure.com) に移動します。

3. **サインイン**ダイアログ ボックスで、ラボのホスティングプロバイダーから提供された管理者用の**テナント電子メール**アカウントをコピーして貼り付け、**次へ**を選択します。

4. **パスワードの入力**ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された管理者用の**テナントパスワード**をコピーして貼り付け、「**サインイン**」 を選択します。

5. Azure portal の検索バーに「*Sentinel*」と入力してから、「**Azure Sentinel**」を選択します。

6. 先ほど作成した Azure Sentinel ワークスペースを選択します。

7. 一般セクションから**Log**を選択します。

8. まず、データが保存されている場所を確認する必要があります。攻撃を行ったばかりなので  ログの時間範囲を**過去24時間**に設定します。

9. 次のKQLステートメントを実行します

```KQL
search "temp\\startup.bat"
```

10. 結果は、3つの異なるテーブルについて示しています。
    - DeviceProcessEvents
    - DeviceRegistryEvents
    - Event

    *Device* テーブルは、Defender for Endpoint コネクタに由来します。*Event* テーブルのデータは、エージェント構成を通して接続された Sysmon/Operational Windows Event Logs から入力されます。

    Sysmon と Defender for Endpoint の 2 つの異なるソースからデータを受信しているため、後で結合できる 2 つの KQL ステートメントを作成する必要があります。最初の調査では、それぞれを個別に確認していきます。

    **注:** まれに、データの読み込みプロセスの読み込みに通常よりも時間がかかる場合があります。その場合、テーブルがクエリに数時間表示されないことがあります。*Event* テーブルが表示された場合のみ、続行できます。

11. 最初のデータソースは、WindowsホストからのSysmonです。  以下のKQLステートメントを実行します。

```KQL
search in (Event) "temp\\startup.bat"
```
結果は、イベントテーブルに対してのみ表示されるようになりました。  

12. 行を展開して、レコードに関連するすべての列を表示します。  EventDataやParameterXmlなどのいくつかのフィールドには、構造化データとして保存された複数のデータ項目があります。  これにより、特定のフィールドでのクエリが困難になります。  

13. 次に、各行のデータを解析するKQLステートメントを作成して、意味のあるフィールドを作成する必要があります。GitHubのAzureSentinelコミュニティでは、ParsersフォルダーにParsersの例が多数あります。  ブラウザーで新しいタブを開き、以下に移動します。**https://github.com/Azure/Azure-Sentinel**

14. **Parsers**フォルダーを選択し、次に**Sysmon**フォルダーを選択します。

15. Sysmon-v12.0.txtファイルを選択し確認します。

ファイルの先頭に、Eventテーブルをクエリし、EventDataという名前の変数に格納するLetステートメントが表示されます。
**ヒント:** 次のコード スニペットは、手順 16 のクエリを理解しやすくすることを目的としています。コピーしたり、実行したりしないでください。

```
let EventData = Event
| where Source == "Microsoft-Windows-Sysmon"
| extend RenderedDescription = tostring(split(RenderedDescription, ":")[0])
| project TimeGenerated, Source, EventID, Computer, UserName, EventData, RenderedDescription
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| project-away EventData, EvData  ;
```

ファイルのさらに下に、EventID == 13を調べ、EventData変数を入力として使用している別のletステートメントがあります。  
**ヒント:** 次のコード スニペットは、手順 16 のクエリを理解しやすくすることを目的としています。コピーしたり、実行したりしないでください。

```
let SYSMON_REG_SETVALUE_13=()
{
    let processEvents = EventData
    | where EventID == 13
    | extend RuleName = EventDetail.[0].["#text"], EventType = EventDetail.[1].["#text"], UtcTime = EventDetail.[2].["#text"], ProcessGuid = EventDetail.[3].["#text"], 
    ProcessId = EventDetail.[4].["#text"], Image = EventDetail.[5].["#text"], TargetObject = EventDetail.[6].["#text"], Details = EventDetail.[7].["#text"]
    | project-away EventDetail  ;
    processEvents;
    
};
```
これは良いスタートのように見えます。

16. 上の 2 つのステートメントにより、Event テーブル内の Sysmon を使用して、すべての Registry Key Set Value 行を表示するための独自の KQL ステートメントを作成します。次の KQL クエリを実行します。

**重要:** エラーを防止するため、最初に KQL クエリを*メモ帳*に貼り付けてから、*新しいクエリ 1* のログ ウィンドウにコピーしてください。

```KQL
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| extend RenderedDescription = tostring(split(RenderedDescription, ":")[0])
| project TimeGenerated, Source, EventID, Computer, UserName, EventData, RenderedDescription
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| project-away EventData, EvData  
| extend RuleName = EventDetail.[0].["#text"], EventType = EventDetail.[1].["#text"], UtcTime = EventDetail.[2].["#text"], ProcessGuid = EventDetail.[3].["#text"], 
    ProcessId = EventDetail.[4].["#text"], Image = EventDetail.[5].["#text"], TargetObject = EventDetail.[6].["#text"], Details = EventDetail.[7].["#text"]
    | project-away EventDetail 
```

   ![スクリーンショット](../Media/SC200_sysmon_query1.png)

17. ここから引き続き検出ルールを作成できますが、このKQLステートメントは、他の検出ルールのKQLステートメントで再利用できるように見えます。  「ログ」ウィンドウで、「**保存**」、「**関数として保存**」の順に選択します。「保存」 フライアウトで、次のように入力して関数を保存します。

    関数名: Event_Reg_SetValue 
    カテゴリ: Sysmon

18. 「**保存**」を選択し、「+」季語を選択して、新しいログ クエリ タブを開きます。次に、以下の KQL ステートメントを実行します。

```KQL
Event_Reg_SetValue
```
現在のデータ収集によっては、多くの行を受け取る可能性があります。  これは予測されていることです。  次のタスクは、特定のシナリオにフィルターをかけることです

19. 以下の　KQL　ステートメントを実行します。

```KQL
Event_Reg_SetValue | search "startup.bat"
```
これにより、特定のレコードが返され、データを確認して、行を識別するために何を変更できるかを確認できます

20. 脅威インテリジェンスから、脅威アクターがreg.exeを使用してレジストリキーを追加していることがわかります。  ディレクトリはc：\ tempです。startup.batは別の名前にすることができます。次のスクリプトを実行します。

```KQL
Event_Reg_SetValue 
| where Image contains "reg.exe"

```
これは良いスタートです  次に、c：\ tempディレクトリの結果のみを返す必要があります。

21. 続いて、以下のKQLステートメントを実行します:

```KQL
Event_Reg_SetValue 
| where Image contains "reg.exe"
| where Details startswith "C:\\TEMP"
```

これは良い検出ルールのように見えます。  

22. アラートについてできるだけ多くのコンテキストを提供することにより、セキュリティ運用アナリストを支援することが重要です。これには、調査グラフで使用するエンティティの投影が含まれます。  次のクエリを実行します。

```KQL
Event_Reg_SetValue 
| where Image contains "reg.exe"
| where Details startswith "C:\\TEMP"
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = UserName

```

23. 適切な検出ルールができたので、クエリのあるログウィンドウで、コマンド バーの 「**新しいアラート ルール**」 を選択し、「**Azure Sentinel アラートの作成**」 を選択します。

24. これにより、分析ルール　ウィザードが起動します。  全般タブに次のように入力します

    名前: Sysmon Startup RegKey
    説明: Sysmon Startup Regkey in c:\temp
    タクティクス: 永続化
    重大度: 高

「**次へ: ルール ロジックの設定 >**」を選択します。

25. 「**ルール ロジックの設定**」 タブで、**ルール クエリ**が既に入力されているはずです。「**-> Test with current data**」 (現在のデータでテストする) を選択して、現在の構成で受信できた 1 日あたりのアラート数を確認します。

26. クエリスケジューリングの場合、次のように設定します。

- もう一度クエリを実行する: 5 分
- 最後からのデータを見てください：1 日

**注:** じデータに対して意図的に多くのインシデントを生成しています。これにより、ラボはこれらのアラートを使用できるようになります。この構成変更を行うと、受信するアラートの数が変化する場合があります。  「**-> Test with current data**」 (現在のデータでテストする) を選択して、変更された構成で受信できた 1 日あたりのアラート数を確認します。

27. 残りのオプションは既定値のままにします。  「**次へ: インシデント設定 >**」ボタンを選択します。

28. *インシデントの設定 (プレビュー)* タブで、これらの構成が次のように設定されていることを確認します。 

- インシデントの設定：有効
- アラート グループ：無効

「**次へ: 自動応答 >**」ボタンを選択します。

29. 自動応答タブで次のように設定します。

- *PostMessageTeams-OnAlert* を選択します。

「**次へ: レビュー**」ボタンを選択します。

30. レビュータブで、**作成**を選択します。

### タスク 2: エンドポイントのDefenderによる攻撃1の検出

このタスクでは、Microsoft Defender for Endpoint が構成されたホストで**攻撃 1** の検出を作成します。

1. Azure Sentinelポータルで、全般セクションから**ログ**を選択します。

2. まず、データが保存されている場所を確認する必要があります。攻撃を行ったばかりなので  

    ログの時間範囲を過去24時間に設定します。

3. 以下の　KQL　ステートメントを実行します。

```KQL
search "temp\\startup.bat"
```

4. 結果は、3つの異なるテーブルについて示しています。
    DeviceProcessEvents
    DeviceRegistryEvents
    Event

    *Device* テーブルは、Defender for Endpoint コネクタに由来します。*Event* テーブルのデータは、エージェント構成を通して接続された Sysmon/Operational Windows Event Logs から入力されます。

    SysmonとDefenderforEndpointの2つの異なるソースからデータを受信しているため、  後で結合できる 2 つの KQL ステートメントを作成する必要があります。しかし、最初の調査では、それぞれを個別に確認していきます。

    **注:** まれに、データの読み込みプロセスの読み込みに通常よりも時間がかかる場合があります。その場合、テーブルがクエリに数時間表示されないことがあります。結果に *Device* テーブルが表示されない場合は、タスク 3 に進み、後でここに戻ります。

5. この検出は、Defender forEndpoint からのデータに焦点を当てます。  以下の　KQL　ステートメントを実行します。

```KQL
search in (Device*) "temp\\startup.bat"
```

6. テーブル--DeviceRegistryEventsは、データがすでに正規化されており、クエリが簡単にできるように見えます。  行を展開して、レコードに関連するすべての列を表示します。

7. 脅威インテリジェンスから、脅威アクターがreg.exeを使用してレジストリキーを追加していることがわかります。  ディレクトリはc：\ tempです。startup.batは別の名前にすることができます。  このKQLステートメントを入力します。

```KQL
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where InitiatingProcessFileName == "reg.exe"
| where RegistryValueData startswith "c:\\temp"
```

これは良い検出ルールのように見えます。  

8. アラートについてできるだけ多くのコンテキストを提供することにより、セキュリティオペレーションセンターアナリストを支援することが重要です。これには、調査グラフで使用するエンティティの投影が含まれます。次のクエリを実行します。

```KQL
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where InitiatingProcessFileName == "reg.exe"
| where RegistryValueData startswith "c:\\temp"
| extend timestamp = TimeGenerated, HostCustomEntity = DeviceName, AccountCustomEntity = InitiatingProcessAccountName
```

   ![スクリーンショット](../Media/SC200_sysmon_query2.png)

9.  適切な検出ルールができたので、クエリのあるログ ウィンドウで、コマンド バーの 「**新しいアラート ルール**」 を選択します。  次に、「**Azure Sentinel アラートの作成**」 を選択します。

10. これにより、分析ルール　ウィザードが起動します。  全般タブに次のように入力します

    名前: D4E Startup RegKey
    説明: D4E Startup Regkey in c:\temp
    タクティクス: 永続化
    重大度: 高

11. 「**次へ: ルール ロジックを設定　>**」ボタンを選択します。

12. 「ルール ロジックの設定」 タブで、**ルール クエリ**が既に入力されているはずです。

13. クエリスケジューリングの場合、次のように設定します。

- もう一度クエリを実行する: 5 分
- 最後からのデータを見てください：1 日

**注:** じデータに対して意図的に多くのインシデントを生成しています。  これにより、ラボはこれらのアラートを使用できるようになります。

14. 残りのオプションは既定値のままにします。  「**次へ: インシデントの設定 >**」を選択します。

15. *インシデントの設定 (プレビュー)* には、以下を設定します。 

- インシデントの設定：有効
- アラート グループ：無効

「**次へ: 自動応答 >**」を選択します。

16. 自動応答タブで次のように設定します。

- *PostMessageTeams-OnAlert* を選択します。

「**次へ: レビュー**」 をクリックします。

17. 確認および作成 タブで、**作成** を選択します。

### タスク 3: SecurityEventによる攻撃2の検出

このタスクでは、セキュリティ イベント コネクタと Sysmon がインストールされているホストで*攻撃 2* の検出を作成します。

1. Azure Sentinel メニューの 全般 セクションで **ログ** を選択します。

2. まず、データが保存されている場所を確認する必要があります。攻撃を行ったばかりなので  

    ログの時間範囲を過去24時間に設定します。

3. 以下の　KQL　ステートメントを実行します。

```KQL
search "administrators"
```

4. 結果は次の表を示します。
    Event
    SecurityEvent

5. 最初のデータソースはSecurityEventです。特権グループへのメンバーの追加を識別するためにWindowsが使用するイベントIDを調査するときが来ました。探していた EventID と Event は "4732 - A member was added to a security-enabled local group" でした。次のスクリプトを実行して確認します。

```KQL
SecurityEvent
| where EventID == "4732"
| where TargetAccount == "Builtin\\Administrators"

```

6. 行を展開して、レコードに関連するすべての列を表示します。  探しているユーザー名は表示されません。  問題は、ユーザー名を保存する代わりに、セキュリティ識別子 (SID) が保存されるということです。  次の KQL は、SID を照合して、Administrators グループに追加された TargetUserName にデータを入力しようとします。

```KQL
SecurityEvent
| where EventID == "4732"
| where TargetAccount == "Builtin\\Administrators"
| extend Acct = MemberSid, MachId = SourceComputerId 
| join kind=leftouter (
     SecurityEvent 
     | summarize count() by TargetSid, SourceComputerId, TargetUserName
     | project Acct1 = TargetSid, MachId1 = SourceComputerId, UserName1 = TargetUserName
) on $left.MachId == $right.MachId1, $left.Acct == $right.Acct1 

```

これは良い検出ルールのように見えます。  

   ![スクリーンショット](../Media/SC200_sysmon_attack3.png)

**注:** ラボで使用されるデータセットが小さいため、このKQLは期待される結果を返さない場合があります。

7. アラートについてできるだけ多くのコンテキストを提供することにより、セキュリティ運用アナリストを支援することが重要です。これには、調査グラフで使用するエンティティの投影が含まれます。  次のクエリを実行します。

```KQL
SecurityEvent
| where EventID == "4732"
| where TargetAccount == "Builtin\\Administrators"
| extend Acct = MemberSid, MachId = SourceComputerId 
| join kind=leftouter (
     SecurityEvent 
     | summarize count() by TargetSid, SourceComputerId, TargetUserName
     | project Acct1 = TargetSid, MachId1 = SourceComputerId, UserName1 = TargetUserName
) on $left.MachId == $right.MachId1, $left.Acct == $right.Acct1 
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = UserName1
```

8. 適切な検出ルールができたので、クエリのあるログ ウィンドウで、コマンド バーの 「**新しいアラート ルール**」 を選択し、「**Azure Sentinel アラートの作成**」 を選択します。

9. これにより、分析ルール　ウィザードが起動します。  全般タブに次のように入力します

- 名前: SecurityEvents Local Administrators User Add 
- 説明: SecurityEvents Local Administrators User Add 
- タクティクス: 特権エスカレーション
- 重大度: 高

「**次へ: ルール ロジックを設定　>**」ボタンを選択します。

10. ルールロジックの設定タブで、ルールクエリエンティティとマップエンティティが既に入力されている必要があります。

11. クエリスケジューリングの場合、次のように設定します。

- もう一度クエリを実行する: 5 分
- 最後からのデータを見てください：1 日

**注:** じデータに対して意図的に多くのインシデントを生成しています。  これにより、ラボはこれらのアラートを使用できるようになります。

12. 残りのオプションは既定値のままにします。  「**次へ: インシデントの設定 >**」を選択します。

13. *インシデントの設定 (プレビュー)* には、以下を設定します。

- インシデントの設定：有効
- アラート グループ：無効

「**次へ: 自動応答 >」を選択します。**

14. 自動応答タブで次のように設定します。

- **PostMessageTeams-OnAlert** を選択します。

「**次へ: 確認 >**」ボタンを選択します。

15. レビュー タブで、**作成**を選択します。

## 演習 7 に進みます。
