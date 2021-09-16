# モジュール 8 - ラボ 1 - 演習 1 - AzureSentinel で脅威ハンティングを実行する

## ラボ シナリオ

あなたは Azure Sentinel を実装済みの会社で働いているセキュリティ オペレーションアナリストです。あなたはコマンドと制御 (C2) テクニックについて脅威インテリジェンスを受け取りました。  その脅威に対して捜索とウォッチを実行する必要があります。

**注：** このラボで使用するログデータは、**モジュール7 - 演習5** で作成した DNSトンネリングアタックです。  

**注：** 前のモジュールでデータを探索するプロセスをすでに経験しているため、ラボでは開始するための KQL ステートメントを提供しています。  

### タスク 1: ハンティングクエリの作成

このタスクでは、捜索クエリを作成し、結果をブックマークして、ライブストリームを作成します。

1. Edge　ブラウザーで Azure portal (https://portal.azure.com) に移動します。

2. **サインイン** ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントの電子メール**アカウントをコピーして貼り付け、「**次へ**」を選択します。

2. **パスワードの入力**ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントパスワード**をコピーして貼り付け、**「サインイン」** を選択します。

5. Azure ポータルの検索バーに「*Sentinel*」と入力し、「**Azure Sentinel**」を選択します。

6. Azure Sentinel ワークスペースを選択します。

7. 「**ログ**」を選択する。 

8. 新規クエリ1のスペースに以下の KQL ステートメントを入力します。

```KQL
let lookback = 2d;
DeviceEvents
| where TimeGenerated >= ago(lookback) 
| where ActionType == "DnsQueryResponse"
| extend c2 = substring(tostring(AdditionalFields.DnsQueryString),0,indexof(tostring(AdditionalFields.DnsQueryString),"."))
| where c2 startswith "sub"
| summarize count() by bin(TimeGenerated, 3m), c2
| where count_ > 5
| render timechart 
```

9. このステートメントの目的は、C2 が一貫してビーコンを出しているかどうかを確認するための視覚化を提供することです。  3m の設定を 30s 以上に調整してください。同時に  count_ > 5 の設定を 1 に変更して、影響を確認します。

10. これで、C2サーバにビーコン送信されている DNS リクエストが特定できました。  次に、どのデバイスがビーコンになっているかを確認します。  次の KQL ステートメントを入力します。

```KQL
let lookback = 2d;
DeviceEvents
| where TimeGenerated >= ago(lookback) 
| where ActionType == "DnsQueryResponse"
| extend c2 = substring(tostring(AdditionalFields.DnsQueryString),0,indexof(tostring(AdditionalFields.DnsQueryString),"."))
| where c2 startswith "sub"
| summarize cnt=count() by bin(TimeGenerated, 5m), c2, DeviceName
| where cnt > 15
```

**注：** 生成されるログデータは、1 つのデバイス(WIN1)からのみです。

11. Azure Sentinel ポータルの **脅威管理**領域で「**ハンティング**」ページを選択します。

12. コマンド バーで「**新しいクエリ**」を選択します。

13. カスタムクエリには、次のKQLステートメントを入力します。

```KQL
let lookback = 2d;
DeviceEvents
| where TimeGenerated >= ago(lookback) 
| where ActionType == "DnsQueryResponse"
| extend c2 = substring(tostring(AdditionalFields.DnsQueryString),0,indexof(tostring(AdditionalFields.DnsQueryString),"."))
| where c2 startswith "sub"
| summarize cnt=count() by bin(TimeGenerated, 5m), c2, DeviceName
| where cnt > 15
```

14. 名前には「*C2 Hunt*」と入力します。

15. エンティティマッピングには：

    ホストには「**DeviceName**」を選択し、「**追加**」を選択します。
    タイムスタンプで「**TimeGenerated**」を選択し、「**追加**」を選択します

16. 「**作成**」を選択します。

17. クエリの一覧から　*C2 Hunt*　を検索します。フィルターが設定されていると検索にヒットしない可能性があるので、フィルターはすべて削除してください。

18. リストの中から「**C2 Hunt**」を選択します。

19.  画面の右下の「**クリエの実行**」ボタンを選択します。

20. 結果のカウントが、フライアウトの上部に表示されます。

21. 「**結果を表示**」を選択します。

22. 結果の最初の行を選択します。 

23. 「**ブックマークの追加**」を選択します。

24. 表示されるペインで、「**作成**」を選択します。

25. Sentinel の **ハンティング** ページに戻ります。

26. 「**ブックマーク**」タブを選択します。

27. 結果の一覧で ブックマークを選択します。

28. フライアウトペインで、「**調査**」を選択します。

29. 表示されたグラフを探索してみてください。

30. Azure portal の**ハンティング**ページに戻ります。

31. 「**クエリ**」タブを選択します

32. 「**C2 Hunt**」クエリを選択します。

33. 行の右端にある **「...」** を選択して、コンテキストメニューを開きます。

34. 「**ライブストリームに追加**」を選択します。

35. **ライブストリーム** タブでクエリーが実行されていることを確認してください。画面の右下の**ライブストリームを開く**をクリックします。

36. クエリの中から、以下の２行を削除します。ライブストリームクエリには時間間隔を指定することはできません。

    - let lookback = 2d;
    - | where TimeGenerated >= ago(lookback) 

37. **保存** をクリックします。

38. **再生** をクリックして、ライブストリームを再開します。

39. **モジュール7 - 演習5** で実行した C2.ps1 が WIN1 上で実行されている場合は、攻撃の状況をハンティングすることができます。

# 演習 2 に進みます。
