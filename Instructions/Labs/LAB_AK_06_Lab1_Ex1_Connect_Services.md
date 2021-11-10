# モジュール 6 - ラボ 1 - 演習 1 - データコネクタを使用して Azure Sentinel にデータを接続する

## ラボ シナリオ

あなたは Azure Sentinel を実装した企業で働いているセキュリティ オペレーションアナリストです。組織内の多くのデータ ソースからのログ データを接続する方法について学習する必要があります。組織には、Microsoft 365、Microsoft 365 Defender、Azure リソース、Azure 以外の仮想マシン、ネットワーク アプライアンスからのデータがあります。

あなたは、Azure Sentinel データ コネクタを使用して、さまざまなソースからのログ データを統合することを計画しています。組織の各データ ソースを適切な Azure Sentinel データ コネクタにマップする管理用のコネクタ計画を作成する必要があります。

**重要な警告!**  仮想マシン WIN1 と WIN2 はモジュール７で使います。   仮想マシンを保存します。   保存せずにラボを終了する場合は、WIN1 と WIN2 にコネクタを再度インストールする必要があります。

### タスク 1: Azure Sentinel ワークスペースにアクセスします。

このタスクでは、Azure Sentinel ワークスペースにアクセスします。

1. 管理者として WIN1 仮想マシンにログインします。パスワードは **Pa55w.rd** です。  

2. Microsoft Edge ブラウザーを開きます。

3. Microsoft Edgeブラウザーで Azure ポータルに移動します https://portal.azure.com。

4. **サインイン**ダイアログボックスで、ラボ ホスティング プロバイダーから提供された**テナントの電子メール**アカウントをコピーして貼り付け、「**次へ**」 を選択します。

5. **パスワードの入力**ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントパスワード** をコピーして貼り付け、「**サインイン**」を選択します。

6. Azure ポータルの検索バーに 「*Sentinel*」 と入力し、「**Azure Sentinel**」 を選択します。

7. 前のラボで作成した Azure Sentinel ワークスペースを選択します。

### タスク 2: Azure Active Directory コネクタを接続する

このタスクでは、Azure Active Directory コネクタを Azure Sentinel に接続します。

1. 構成領域で、 「**データコネクタ**」を選択します。  データ コネクタ ページで、リストから **Azure Active Directory** タイルを選択します。

2. コネクタ情報ブレードで「**コネクタページを開く**」を選択します。

3. 構成領域から「**サインインログ**」および「**監査ログ**」オプションを選択し、「**変更の適用**」を選択します。

### タスク 3: Azure Active Directory Identity Protection コネクタを接続する

このタスクでは、Azure Active Directory Identity Protection コネクタを Azure Sentinel に接続します。

1. データ コネクタ タブで、リストから 「**Azure Active Directory Identity Protection**」 コネクタを選択します。

2. コネクタ情報ブレードで「**コネクタページを開く**」を選択します。

3. 「構成」 領域から 「**接続**」 ボタンを選択します。

### タスク 4: Azure Defender(Microsoft Defender for Cloud) コネクタを接続する

このタスクでは、Azure Defender コネクタを接続します。

1. データ コネクタ タブで、リストから 「**Microsoft Defender for Cloud**」 コネクタを選択します。

2. コネクタ情報ブレードで「**コネクタページを開く**」を選択します。

3. 「サブスクリプション」 の下の 「構成」 領域で、Azure サブスクリプションを選択し、「**接続**」 をクリックします。

4. 「接続」メッセージを確認し、「**OK**」 を選択して続行します。これで、Azure サブスクリプションの「状態」が「*接続済み*」になります。

5. 「インシデントの作成 - 推奨!」 領域で、「**有効にする**」 を選択します。

### タスク 5: Microsoft Cloud App Security(Microsoft Defender for Cloud Apps) コネクタを接続する。

このタスクでは、Microsoft Cloud App Security コネクタをに接続します。

1. データ コネクタ タブで、リストから 「**Microsoft Defender for Cloud Apps**」 コネクタを選択します。

2. コネクタ情報ブレードで「**コネクタページを開く**」を選択します。

3. 「**アラート**」 を選択し、「**変更の適用**」 を選択します。

### タスク 6: Microsoft Defender for Office 365 に接続する

このタスクでは、Microsoft Defender for Office 365 コネクタを接続します。

1. データ コネクタ タブで、リストから「**Microsoft Defender for Office 365 (プレビュー)**」コネクタを選択します。

2. コネクタ情報ブレードで「**コネクタページを開く**」を選択します。

3. 構成領域で、「**接続**」を選択します。

### タスク 7: Microsoft Defender for Identity コネクタに接続する

このタスクでは、Microsoft Defender for Identity コネクタ確認します。

1. データ コネクタ タブで、リストから 「**Microsoft Defender for Identity**」 コネクタを選択します。

2. コネクタ情報ブレードで「**コネクタページを開く**」を選択します。

3. 接続オプションを確認しますが、接続はしません。画面の確認だけを行ってください。

### タスク 8: Microsoft Defender for Endpoint コネクタに接続する

このタスクでは、Microsoft Defender for Endpoint コネクタを接続します。

1. データ コネクタ タブで、リストから 「**Microsoft Defender for Endpoint**」 コネクタを選択します。

2. コネクタ情報ブレードで「**コネクタページを開く**」を選択します。

3. 構成領域で、「**接続**」を選択します。

### タスク 9: Microsoft 365 Defender コネクタを接続する

このタスクでは、Microsoft 365 Directory コネクタを接続します。

1. データ コネクタ タブで、リストから「**Microsoft 365 Defender (プレビュー)**」コネクタを選択します。

2. コネクタ情報ブレードで「**コネクタページを開く**」を選択します。

3. Microsoft Defender for Endpoint のすべてのチェックボックスを選択します。

4. 「**変更の適用**」を選択します。

## 演習 2 に進みます。
