# easi - Easy Agent for SORACOM Inventory

easi(イージー)はソラコム社のデバイス管理サービスSORACOM Inventoryを使ってマイコンを遠隔操作するためのツールです。SORACOM Inventoryの説明はこちら

https://soracom.jp/services/inventory/

主にSeeed社のマイコンモジュールWio LTE JP Versionをターゲットにしています。

簡単にマイコンを遠隔操作することができる以下の特徴を持ちます。

- READ / WRITE / EXECUTEのオペレーションをマイコン内の処理と結びつけ
- SIM経由のブートストラップ

## 取得方法

このリポジトリをクローンします。
easi.inoをArduino IDEで開くとそのままコンパイル、書き込みできます。
Arduino IDE およびライブラリの導入については、以下の資料をご覧ください。

https://dev.soracom.io/jp/start/lte_hw_wio-lte/

## 使用方法

プログラムを書き込んだらWio LTEにSORACOM Air SIMを挿し、電源を入れます。
しばらくすると赤いLEDが点灯し、接続済みの状態になります。

SORACOMのユーザーコンソールにログインし、左サイドメニューからSORACOM Inventory → デバイス管理を選択します。
https://console.soracom.io/#/devices?coverage_type=jp

Endpointがwiolteとなっているデバイスが表示されていればOKです。
されていなければ電源再投入、プログラム書き込み直しなどを試してください。

デバイスを選択し、詳細ボタンをクリックするとデバイスの状態を表すリソースと、READ/ WRITE / EXECUTEなどのボタンが表示されます。

Reboot /3/0/4となっているリソースを探し、EXECUTEのボタン(右向き三角ボタン)をクリックし、コマンド実行をクリックしてみてください。Wio LTEのLEDが赤く光って再起動すれば成功です。

## カスタマイズ方法

インスタンスの追加とオペレーションの登録の2つの方法でカスタマイズすることができます。

インスタンスの追加により、LwM2MのオブジェクトをSORACOM Inventoryの管理対象とすることができます。

LwM2Mのオブジェクトは以下のサイトに公開されています。このうちID:0 〜 ID:9、ID:3200 〜 3203、ID:3300 〜 3350を追加することができます。

http://www.openmobilealliance.org/wp/omna/lwm2m/lwm2mregistry.html

例えば以下のように記載することで、オブジェクトID:3のDeviceオブジェクトを2つ登録することができます。

```clang
addInstance(3, 0);
addInstance(3, 1);
```

オペレーションの登録によりREAD / WRITE / EXECUTEの呼び出しと、プログラムの関数を結びつけることができます。

例えばREADオペレーションの場合は以下のように登録します。

```clang
setReadResourceOperation(オブジェクトID, インスタンスID, リソースID, &関数);
```

関数は`void(Lwm2mTLV *)`のシグニチャを持つ関数です。例えばREAD /3/0/2(シリアル番号取得)の場合、以下のようにします。

```clang
void getSerial(Lwm2mTLV *tlv){
  strcpy((char *)&tlv->bytesValue[0], "123456789");
};
```

TLV(Type-Length-Value)とはLwM2Mなどで使用されるデータ形式です。
LwM2MではString、Integerなど7種類のリソース種類がありますが、それぞれの種類によりデータの格納方法が決まっています。
本プログラムでは以下のようにLwM2MTLV構造体の各メンバーにより値を受け渡しします。

|リソース種類|メンバー|
|:--|:--|
|Integer|tlv->intValue|
|Boolean|tlv->intValue (true: 1、false: 0)|
|Time|tlv->intValue|
|Float|tlv->floatValue|
|String|tlv->bytesValue(最後のバイトを0とすること)|
|Opaque|バイナリをtlv->bytesValue、長さをtlv->bytesLen|
|Objlnk|オブジェクトIDをtlv->ObjectLinkValue、インスタンスIDをtlv->InstanceLinkValue|


READは値をtlvに格納し、Writeはtlvに格納された値を使います。EXECUTEは厳密にはTLVではありませんが、シグニチャを統一するためOpaqueと同じ形式で値を渡します。

## その他のオブジェクトの登録

lwm2mResource.cにオブジェクトの定義を追加し、lwm2mObjectTemplates配列に追加することで対応可能です。

## 対応していないこと

- Observe
- Objectに対するREAD
- リソースインスタンス(リソースの中に複数の値が存在するリソース)の対応

