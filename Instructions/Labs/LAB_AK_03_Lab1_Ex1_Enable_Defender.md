---
lab:
    title: '演習 1 - Microsoft Defender for Cloud の有効化'
    module: 'モジュール 3 – Microsoft Defender for Cloud を使用して脅威を軽減する'
---

# モジュール 3 - ラボ 1 - 演習 1 - Microsoft Defender for Cloud の有効化

## ラボ シナリオ

あなたは、Microsoft Defender for Cloud を使用して、クラウドのワークロード保護を実装している企業のセキュリティ運用アナリストです。  このラボでは、Microsoft Defender for Cloud を有効化します。


### タスク 1: Azure ポータル にアクセスし、サブスクリプションを設定します。

このタスクでは、このラボと今後のラボを完了するために必要なAzureサブスクリプションを設定します。

1. 管理者として WIN1 仮想マシンにログインします。パスワードは**Pa55w.rd** です。  

2. Microsoft Edge 起動するか、既に起動している場合は、新しいタブを開きます。

3. Microsoft Edgeブラウザーで Azure portal (https://portal.azure.com) に移動します。

4. **サインイン** ダイアログ ボックスで、ラボ ホスティング プロバイダーの提供した管理者ユーザー名のテナント電子メール アカウントをコピーして貼り付け、「**次へ**」を選択します。

5. **パスワードの入力**ダイアログ ボックスで、ラボ ホスティング プロバイダーの提供した管理者のテナント パスワードをコピーして貼り付け、**サインイン**します。

6. Azureポータルの検索バーに「*サブスクリプション*」を入力し「**サブスクリプション**」を選択します。 

7. 「*Azure パス - スポンサーシップ*」サブスクリプション (もしくは、選択した言語で相当する名前) が表示されたら、タスク #2 に進んでください。表示されない場合は、テナント管理者のユーザー資格情報を使用して Azure サブスクリプションを作成する方法を、講師に質問してください。**注:** サブスクリプション作成のプロセスには、最大で 10 分かかる場合があります。 

>**重要:** これらのラボは、クラス中に 10 米ドル未満の Azure サービスを使用するように設計されています。


### タスク 2: Log Analytics ワークスペースを作成する。

このタスクでは、Microsoft Defender for Cloud を使用して、Log Analytics ワークスペースを作成します。

1. Azureポータルの検索バーに「 *LogAnalytics*」を入力し 「**LogAnalyticsワークスペース**」を選択します。

2. コマンド バーから 「**+ 作成**」を選択します。

3. リソース グループの「**新規作成**」 を選択します

4. 「*RG-Defender*」と入力して、「 **OK**」を選択します。

5. 「名前」には、*uniquenameDefender*のような一意の名前を入力します。

6. 「**確認および作成**」を選択します。

7. ワークスペースの検証に合格したら、「**作成**」を選択します。新しいワークスペースがプロビジョニングされるのを待ちます。これには数分かかる場合があります。


### タスク 3: Microsoft Defender for Cloud を有効化する。

このタスクでは、Microsoft Defender for Cloud を有効化および構成します。

1. Azure portal の「検索」バーに、「*Defender*」と入力してから、「**Microsoft Defender for Cloud**」を選択します。

2. 「**開始**」ページで、「**アップグレード**」セクションに移動して、サブスクリプションが選択されていることを確認したから、ページの下部で、「**アップグレード**」ボタンを選択します。「*トライアルが開始されました*」通知が表示されるまで待機します。**ヒント:** 上部バーの「ベル」ボタンをクリックして、Azure portal の通知を確認します。

3. 次のページは、すでにサブスクリプションに含まれている仮想マシンにエージェントをインストールするオプションを示しています。**ここでは何もしない**。

4. 「ポータル」メニューの「管理」領域で、「**環境設定**」を選択します。

5. 「**Azure Pass - Sponsorship**」サブスクリプション (または、選択されている言語の同等の名前) を選択します。 

6. 「*すべての Microsoft Defender for Cloud プランを有効化する*」の下で、有効化されているさまざま機能、「*Microsoft Defender for*」列の下でに保護されている Azure リソースを確認します。

7. 設定領域から 「**自動プロビジョニング**」 を選択します。

8. 自動プロビジョニング-拡張機能を確認します。**Azure VM の Log Analytics エージェント** が **オフ**になっていることを確認します。

9. ページの右上の「x」を選択して、「設定」ページをとじ、「**環境設定**」に戻り、サブスクリプションの左にある「>」を選択します。

10. 以前に作成したLog Analytics ワークスペース、*uniquenameDefender* を選択し、使用可能なオプションや価格を確認してください。「**すべて有効にする**」を選択し、「**保存**」を選択します。


### タスク 4: オンプレミスのサーバーにAzure Arcをインストールする。

オンプレミスサーバーのオンボーディングを簡単にするため。  Azure Arcをインストールすると、Azureがオンプレミスサーバーを管理できるようになります。

このタスクでは、オンプレミスサーバーにAzureArcをインストールします。

1. 管理者として WINServer仮想マシンにログインします。パスワードは**Pa55w.rd**  

2. Microsoft Edgeブラウザーで Azure portal (https://portal.azure.com) に移動します。

3. **サインイン** ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントの電子メール**アカウントをコピーして貼り付け、「**次へ**」を選択します。

4. **パスワードの入力**ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントパスワード** をコピーして貼り付け、「**サインイン**」を選択します。

5. Azureポータルの検索バーに「*Arc*」と入力し「**AzureArc**」を選択します。

6. 「ナビゲーション」ペインの「**インフラストラクチャ**」の下で、「**サーバー**」を選択します

7. 「**+ 追加**」を選択します。

8. 単一サーバーの追加セクションで「**スクリプトの生成**」を選択します。

9. 「**次へ**」を選択して、「リソースの詳細」タブに移動します。

10. 先ほど作成したリソース グループを選択します。ヒント: *RG-Defender*

    >**注:** リソース グループをまだ作成していない場合は、もう1つのタブを開いてリソース グループを作成し、最初からやり直します。

11. 「*サーバーの詳細*」および「*ネットワーク接続*」オプションを確認します。「**次へ**」を選択して、「タグ」タブに移動します。

12. 「**次へ**」を選択して、「スクリプトをダウンロードして実行」タブに移動します。

13. 「**登録**」を選択します。

    >**注:** 処理が完了するまで少なくとも 3 分お待ちください。

14. 下にスクロールして、「**ダウンロード**」ボタンを選択します。ヒント: ブラウザーがダウンロードをブロックした場合は、ブラウザーでアクションを実行してダウンロードを許可してください。Microsoft Edge ブラウザーで、3 つドット "..." を選択してから、「**維持 (Keep)**」を選択します。 

15. 「Windows スタート」ボタンを右クリックし、「**Windows PowerShell (Admin)**」をクリックします。

16. プロンプトが表示されたら、ユーザー名」に「Administrator」と入力します。

17. プロンプトが表示されたら、パスワードとして「Pa55w.rd」と入力します。

18. 「cd C:\Users\Administrator\Downloads」と入力します

19. *Set-ExecutionPolicy -ExecutionPolicy Unrestricted* を入力しEnterキーを押します。

20. 「すべてにはい」の場合は**A** を入力し、Enterキーを押します。

21. *「.\OnboardingScript.ps1」* と入力し、Enter キーを押します。

22. **R** を入力して 1 回実行し、Enter キーを押します (これには数分かかる場合があります)。

23. PowerShell の出力の最後の行の指示に従って、デバイスの登録を完了します。  これには、ブラウザーを介したデバイスの認証が含まれます。  URL (https://microsoft.com/devicelogin) をコピーして、新しい Microsoft Edge ブラウザー タブに入力します。「Windows PowerShell」ウィンドウに戻り、認証用のコードをコピーして、以前に開いたタブに貼り付けて、「**次へ**」を選択します。テナント管理者アカウントを選択し、「*Azure Connected Machine Agent へのサインインを試行しますか?*」ウィンドウで、「**続行 (Continue)**」を選択します。 

24. Windows PowerShell ウィンドウに、「*リソースが Azure に正常にオンボードされました*」という メッセージが表示されてから、スクリプトをダウンロードした Azure portal ページに移動して、「**閉じる**」を選択します。「**サーバーと Azure Arc を追加する**」を閉じて、「Azure Arc **サーバー**」ページに戻ります。

25. WINServer サーバー名が表示されるまで「**更新**」を選択します。

    >**注:** この処理には数分かかります。


### タスク 5: オンプレミスのサーバーを保護する。

このタスクでは、必要なエージェントをWindowsServerに手動でインストールします。

1. **Microsoft Defender for Cloud** に移動し、**はじめに**ページを選択します。

2. 「**作業の開始**」タブを選択します。

3. 下にスクロールして、「*非 Azure サーバーの追加*」セクションで、「**構成**」を選択します。

4. 前に作成したワークスペースの横にある「**アップグレード**」を選択します。  これには数分かかる場合があります。「*ワークスペース用 Defender プランが正常に保存されました*」という通知が表示されるまで待機します。(ワークスペースが表示されない場合はホストOSで開いているAzureポータル画面から参照してみてください)

5. 前に作成したワークスペースの横にある「**＋サーバーの追加**」を選択します。

6. 「**Windows エージェント (64 ビット) のダウンロード**」を選択します。

7. ダウンロードしたファイルを実行します。

8. 「**Agetn Setup Options**」のページが表示されるまで、「**Next**」または「**I Agree**」を選択して、「**Connect the agent to Azure Log Analytics (OMS)**」を選択してから、「**Next**」を選択します。

9. 「**Workspace ID**」と「**Workspace Key**」を Azure portal から「ウィザード ページ」フィールドにそれぞれコピーして貼り付けて、「**Next**」を選択します。

10. インストールを続行します。完了したら「**Finish**」を選択します。

11. 「Microsoft Defender for Cloud」ポータルに移動して、「**インベントリ**」を選択します。

12. 少なくとも 5 分後に WINServer が表示されます。「**最新の情報に更新**」を選択して、確認することが必要となる場合があります。

13. 次のラボに移動して、後で戻って、**Microsoft Defender for Cloud**の「**インベントリ**」セクションを確認します。

# 演習 2 に進みます。
