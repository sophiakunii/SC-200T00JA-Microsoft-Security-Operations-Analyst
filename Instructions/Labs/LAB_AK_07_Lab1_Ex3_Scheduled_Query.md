---
lab:
    title: '演習 3 - スケジュールされたクエリを作成する'
    module: 'モジュール 7 – Microsoft Sentinel を使用して脅威を検出し、調査を実行する'
---
# モジュール 7 - ラボ 1 - 演習 3 - スケジュールされたクエリを作成する

### タスク 1: スケジュール済みクエリを作成します。

このタスクでは、スケジュールされたクエリを作成し、前の演習で作成した Teams チャネルに接続します。

1. 管理者として WIN1 仮想マシンにログインします。パスワードは**Pa55w.rd** です。  

2. **サインイン** ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントのメール** アカウントをコピーして貼り付け、「**次へ**」を選択します。

3. **パスワードの入力**ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントパスワード** をコピーして貼り付け、「**サインイン**」を選択します。

4. Azure portal の検索バーに「*Sentinel*」と入力し、「**Microsoft Sentinel**」を選択します。

5. Microsoft Sentinel ワークスペースを選択します。

6. 構成領域から「**分析**」を選択します。

7. 「**+ 作成**」ボタンを選択し、「**スケジュール済みクエリ ルール**」を選択します。

8. 分析ルール ウィザードの「全般」タブで、名前 *Azure AD Role Assignment Audit Trail* を入力します。

9. 戦術については、「**Persistence**」を選択します。

10. 重大度については、「**低**」を選択します。

11. 「**次へ: ルールのロジックを設定 >**」ボタンを選択します。

12. ルールクエリの場合は、次のKQLステートメントを貼り付けます。

    >**警告**：仮想マシンに貼り付け機能を使用すると、余分な文字 (パイプ) を追加できます。必ず、最初にメモ帳を使用して、以下のクエリを貼り付けます。

```KQL
AuditLogs 
| where isnotempty(InitiatedBy.user.userPrincipalName) and Result == 'success' and OperationName contains "member to role" and AADOperationType startswith "Assign"
| extend InitiatedByUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedFromIP = iff(tostring(AdditionalDetails.[7].value) == '', tostring(AdditionalDetails.[6].value), tostring(AdditionalDetails.[7].value))
| extend TargetUser = tostring(TargetResources.[2].displayName)
| extend TargetRoleName = tostring(TargetResources.[0].displayName)
| project TimeGenerated, InitiatedByUPN, InitiatedFromIP, TargetUser, TargetRoleName, AADOperationType, OperationName
```

>**注:** 「クエリ結果の表示」へのリンクを選択しても、どんな結果やエラーも受け取らない筈です。もしエラーを受け取った場合は、以前の KQL ステートメントと同じようなクエリが表示されることを確認してください。

13. 「*アラート エンリッチメント*」領域で、「*エンティティ マッピング*」-「*新しいエンティティの追加*」をクリックして以下の値を選択します。 

    - 「*エンティティ タイプ*」ドロップダウン リストには「**Account**」を選択します。
    - 「*ID*」ドロップダウン リストには「**FullName**」を選択します。
    - 「*値*」ドロップダウン リストには「**InitiatedByUPN**」を選択します。

    次に、「**新しいエンティティを追加**」をクリックし、次の値を選択します。

    - 「*エンティティ タイプ*」ドロップダウン リストには「**IP**」を選択します。
    - 「*ID*」ドロップダウン リストには「**Address**」を選択します。
    - 「*値*」ドロップダウン リストには「**InitiatedFromIP**」を選択します。

14. 「*クエリスケジュール設定*」で次のように設定します。

    |設定|値|
    |---|---|
    |クエリ実行間隔|5 分|
    |過去のデータの参照|24 時間|

    >**注:** 同じデータに対して意図的に多くのインシデントを生成しています。  これにより、ラボはこれらのアラートを使用できるようになります。

15. **アラートのしきい値** 領域では、オプションを変更しないでください。

    >**注:** ベストプラクティスはアラートルールのKQLクエリステートメントでしきい値を管理することです。

16. **イベント グループ化**領域では、選択したオプションとして、**すべてのイベントを単一のアラートにグループ化する** のままにします。

17. 「**次: インシデントの設定 >**」ボタンを選択します。  

18. *インシデントの設定* タブで、既定のオプションを確認します。

19. 「**次: 自動応答 >**」ボタンを選択します。

20. 「**自動化ルール**」領域で「新規追加」をクリックし、次の値を選択します。

    - 「*オートメーション ルール名*」には「**Automate Active**」と入力します。
    - 「*アクション*」では「*アクションの追加*」をクリックしてドロップダウン リストから「**状態の変更**」を選択します。
    - 「*アクション*」の2番目のドロップダウン リストには「**アクティブ**」を選択します。

最後に「**適用**」ボタンを選択します。

22. 「**次: レビュー >**」ボタンを選択します。
  
23. 「**作成**」 を選択します。


### タスク 2: 新しいルールをテストします。

このタスクでは、新しいスケジュールされたクエリルールをテストします

1. Azureポータルの検索バーに「*Azure Active Directory*」と入力します。「**Azure Active Directory**」を選択します。

2. 「管理」エリアで「**ユーザー**」を選択し、「ユーザー - すべてのユーザー (プレビュー)」ページが表示されるようにしてください。

3. リストでユーザー**ChristieCline**を選択し、「Christie Cline - プロフィール」ページが表示されるようにしてください。

4. 管理領域で「**割り当てられたロール**」を選択し、「Christie Cline - 割り当てられたロール」ページが表示されるようにしてください。

5. コマンド バーから「**+ 割り当ての追加**」を選択します。

6. *割り当ての追加*ページの*メンバーシップ*タブの「*ロールの選択*」の下で、「**ユーザー管理者**」を選択し、「**追加**」を選択します。

8. 「Christie Cline - 割り当てられたロール」と「ユーザー - すべてのユーザー (プレビュー)」ページを、右上の「X」を 2 回選択して閉じます。

9. 「Contoso - 概要」ページで、「*モニタリング*」の下から「**監査ログ**」を選択します。

10. 「**Export data settings**」 (データ設定のエクスポート) を選択して、"Azure Active Directory" のデータ コネクタが、Sentinel で正しく設定されていることを確認します。

11. Sentinel に対して以前に作成した *Log Analytics ワークスペース*の*診断設定*エントリがあることを確認します。

12. 右上の「x」を選択して、ページを閉じます。

13. 「**更新**」をクリックして以前に作成したロールに変更を示す**カテゴリ: RoleManagement** に対するエントリが表示されるのを確認します。

14. Azure portal の検索バーに「*Sentinel*」と入力し、「**Microsoft Sentinel**」を選択します。

15. Microsoft Sentinel ワークスペースを選択します。

16. **インシデント** メニュー オプションを選択します。

    >**注:** トリガーされたアラートの処理には 5 分以上かかる場合があります。次の演習を続けて、後でこのポイントに戻ることができます。インシデント ページの自動更新には、「**インシデント自動更新**」トグルを選択します。

17. 新しく作成したインシデントが表示されます。インシデントを選択し、右側のブレードの情報から「*状態*」が「*アクティブ*」であることを確認します。

## 演習 4 に進みます。
