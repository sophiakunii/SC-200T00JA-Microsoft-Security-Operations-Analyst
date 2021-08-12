# モジュール 1 - ラボ 1 - 演習 1 - Microsoft Defender for Endpoint のデプロイ

## ラボ シナリオ

あなたは Microsoft Defender for Endpoint を実装している企業で働くセキュリティ オペレーションアナリストです。あなたの上司は、いくつかのデバイスをオンボードして、SecOps チームの応答手順で必要な変更に関する情報を提供しようとしています。

最初に、Defender for Endpoint 環境を初期化します。次に、デバイスでオンボード スクリプトを実行し、デプロイ対象の初期デバイスをオンボードします。環境のセキュリティを構成します。最後に、デバイス グループを作成し、適切なデバイスを割り当てます。

### タスク 1 - Microsoft 365 資格情報を取得

ラボを起動すると、無料のトライアル テナントを利用して Microsoft Virtual Lab 環境にアクセスできるようになります。このテナントには自動的に一意のユーザー名とパスワードが割り当てられます。Microsoft Virtual Lab 環境で Azure と Microsoft 365 にサインインするには、このユーザー名とパスワードを取得する必要があります。 

このコースは、学習パートナーが複数の認証済みラボ ホスティング プロバイダーのいずれかを使用して実施することもあり、お使いになっているテナントに関連のあるテナント ID を取得する実際の手順はラボ ホスティング プロバイダーに応じて異なります。このため、コース内での当該情報の取得方法については、講師が必要な指示を行います。後ほど使用できるよう以下の情報に留意してください。

- **テナント サフィックス ID**: この ID は、ラボ全体で Microsoft 365 にサインインする際に使用する onmicrosoft.com アカウント用です。形式は **{username}@M365xZZZZZZ.onmicrosoft.com** です。ZZZZZZ はラボ ホスティング プロバイダーの提供した一意のテナント サフィックス ID です。後で使用できるよう、この ZZZZZZ を記録しておきます。ラボの手順で Microsoft 365 ポータルにサインインするよう指示されたら、ここで取得した ZZZZZZ の値を入力してください。
- **テナント パスワード**: これは、ラボ ホスティング プロバイダーの提供する管理者アカウント向けのパスワードです。
	

### タスク 2: Microsoft Defender for Endpoint の初期化

このタスクでは、Microsoft Defender for Endpoint ポータルの初期化を行います。

**以下の操作はラボ環境のWin1上で実行してください**

1.  管理者として WIN1 仮想マシンにログインします。パスワードは **Pa55w.rd** です。  

2.  Microsoft Edge ブラウザーを開いて「edge ブラウザー更新」を検索し、新しい Microsoft Edge ブラウザーをダウンロードしてインストールします。この手順は、ホスティングされている仮想マシンで確実に Microsoft Edge の最新版を実行する上で重要です。新しい Edge ブラウザーを起動します。

3.  Edge ブラウザーで Microsoft Defender セキュリティ センターに進みます (https://securitycenter.microsoft.com)

4. **サインイン** ダイアログボックスで、ラボ ホスティング プロバイダーの提供した管理者ユーザー名のテナント電子メール アカウントをコピーして貼り付け、「**次へ**」 を選択します。

5. **パスワードの入力**ダイアログ ボックスで、ラボ ホスティング プロバイダーの提供した管理者のテナント パスワードをコピーして貼り付け、**サインイン**します。

**注**: 「このセクションにアクセスできません」というメッセージが表示されたら、何回かリロードしてみてください（最大 5 分程度待つ必要があるかもしれません）。 アクセス ルールでテナントを広める必要があるかもしれません。  

6. **Microsoft セキュリティ センター** セットアップの Step 2 で「**Next**」を選択します。

7. ステップ 3 「**Set up preferences**」で、このトレーニング テナントの管理に適したデータ ストレージの場所を選択します。 ここでは **US** を選択してください。

8. **Preview features** が **On** になっていることを確認してください。

9. 「**Next**」を選択します。  

10. **Creating your Microsoft Defender for Endpoint account** が完了するまで待ちます。

11. **Creating your Microsoft Defender for Endpoint account**の進行状況バーが完了すると、Step 4 のオプションが表示されます。ここでは何もせず、 **Microsoft Defender for Endpoint を使用して開始**を選択します。

### タスク 3: デバイスのオンボード

このタスクでは、デバイスを Microsoft Defender for Endpoint にオンボード（登録）します。

1. https://securitycenter.microsoft.com で Microsoft Defender セキュリティ センターに進みます。現在ポータルを使用していない場合は、**テナントの電子メール**の資格情報を使用してログインします。

2. 左側のメニュー バーで 「**Settings**」 を選択します。

3. **Device Management** セクションで 「**Onboarding**」 を選択します。

4. デバイスのオンボード エリアで 「**Download onboarding package**」 ボタンを選択します。

5. ダウンロードされた zip ファイルをローカル フォルダーに抽出します (［ドキュメント］ フォルダーなど)。

6. 抽出されたファイル (**WindowsDefenderATPLocalOnboardingScript.cmd**) を右クリックし「**管理者として実行**」 を選択します。  Windows SmartScreen が表示されたら「実行」 を選択します。

**注** 既定で、ファイルは 「c:\users\admin\downloads」 ディレクトリにあります。
    
7. スクリプトの質問に対して 「**Y**」 と回答します。完了したら、コマンド画面に「**Successfully onboarded machine to Microsoft Defender for Endpoint**」といった内容のメッセージが表示されます。 

8. ポータルの 「Onboarding」 ページで、"Run a detection test" に表示されているスクリプトをクリップボードにコピーします。新しい **管理者: コマンド プロンプト** ウィンドウを開き、スクリプトをペーストして実行します。

9. Microsoft Defender セキュリティ センターのポータル メニューで 「**Deveice Inventory**」 を選択します。Win1 がリストに表示されます。

**注** デバイスがポータルに表示されるまでに最高 5 分かかることがあります。


### タスク 4: ロールの構成

このタスクでは、デバイス グループで使用するロールを設定します。

1. Microsoft Defender セキュリティ センターのポータルで左側のメニュー バーから 「**Settings**」 を選択します。 

2. **Permission**エリアで 「**Roles**」 を選択します。

3. 「**Turn on roles**」 ボタンを選択します。

4. 「**Add item**」 を選択します。

5. ロールの追加 ダイアログで以下を入力します。
    Role Name: **Live response role**
    Live response capabilities: チェックボックスを選択します
    Advanced: 選択します。

6. 「**Next**」を選択します。

7. Assigned user groups　タブで「**sg-IT**」 を選び、「**Add selected groups**」 を選択します。

8. 「**Save**」を選択します。


### タスク 5: デバイス グループの構成

このタスクでは、アクセス コントロールと自動化の設定が可能なデバイス グループを構成します。

1. 左側のメニュー バーで 「**Settings**」 を選択します。 

2. **Permissions** エリアで 「**Device groups**」 を選択します。

3. 「**Add device groups**」 を選択します。

4. 全般 タブに次の情報を入力します。

- デバイス グループ名: Regular
- 自動化レベル: Full - remediate threats automatically (完全 - 脅威を自動的に修復する)

5. 「**Next**」を選択します。

7. **Devices** タブで、OS の Value を **Windows 10** に設定します。

9. **Preview** タブで、**Show preview** をクリックし、Win1 が表示されることを確認します。

10. **User access** タブで 「**sg-IT**」 を選び、「**Add selected groups**」 を選択します。

7. 「**Done**」を選択します。

8. **Apply changes** 変更をクリックして適用します。


## 演習 2 に進みます。

