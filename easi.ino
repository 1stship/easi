#include "easi.h"
#include <WioLTEforArduino.h>

Lwm2m lwm2m;
WioLTE wio;

void setup() {
  // 初期化
  delay(200);
  wio.Init();
  wio.PowerSupplyLTE(true);
  logText("POWER ON LTE");
  delay(500);
  if (!wio.TurnOnOrReset()) {
    logText("Turn on error");
    return;
  }

  // 接続
  if (!wio.Activate("soracom.io", "sora", "sora")) {
    logText("Connect error");
    return;
  }
  delay(1000);

  // LWM2Mエンドポイントとブートストラップサーバの設定
  lwm2mInit(&lwm2m, "wiolte");
  udpInit(&lwm2m.bootstrapUdp, "bootstrap.soracom.io", 5683);

  // ブートストラップをせず払い出したデバイスIDとキーを使用する場合はこちら
  // char identity[] = "d-01234567890123456789";
  // uint8 psk[16] =  { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
  // lwm2mSetSecurityParam(&lwm2m, identity, &psk[0]);

  // オブジェクトの設定のサンプル
  // 以下のオブジェクトリストのうちID:0 〜 ID:9、ID:3200 〜 3203、ID:3300 〜 3350を登録済み
  // http://www.openmobilealliance.org/wp/omna/lwm2m/lwm2mregistry.html
  
  // デバイスオブジェクトをインスタンス0番として登録
  addInstance(3, 0); 

  // Light Controlオブジェクトをインスタンス0番として登録
  addInstance(3311, 0);

  // オペレーションとメソッドを対応づけのサンプル
  setReadResourceOperation   (   3, 0,    2, &getSerial);    // READ    /3/0/2       でgetSerialが呼ばれるよう設定
  setWriteResourceOperation  (3311, 0, 5850, &turnOnOffLED); // WRITE   /3311/0/5850 turnOnOffLEDが呼ばれるよう設定
  setExecuteResourceOperation(   3, 0,    4, &reboot);       // EXECUTE /3/0/3       でrebootが呼ばれるよう設定

  // ブートストラップ(接続情報取得)実行
  // 成功するまで繰り返す
  while (!lwm2mBootstrap(&lwm2m)){ }
}

void loop() {
  // LWm2mのイベントが無いかチェックし、イベントを処理したらtrue、イベントが無ければfalseを返す
  if (!lwm2mCheckEvent(&lwm2m)){
    delay(100);
  }
}

// READの場合は値をtlvの各要素に代入する
// Integer / Boolean / Timeはtlv->intValue
// Floatはtlv->floatValue
// Stringはtlv->bytesValue
// Opaqueはバイナリをtlv->bytesValue、長さをtlv->bytesLen
// ObjlnkはオブジェクトIDをtlv->ObjectLinkValue、インスタンスIDをtlv->InstanceLinkValue
// にそれぞれ代入する
void getSerial(Lwm2mTLV *tlv){
  strcpy((char *)&tlv->bytesValue[0], "123456789");
};

// WRITEの場合は値がtlvの各要素から渡される
// 対応する要素はREADと同じ
void turnOnOffLED(Lwm2mTLV *tlv){
  if (tlv->intValue){
    wio.LedSetRGB(255, 0, 0);
  } else {
    wio.LedSetRGB(0, 0, 0);
  }
};

// EXECUTEの場合、
// パラメータはOpaqueと同じ形式で渡す(使わなくてもよい)
void reboot(Lwm2mTLV *tlv){
  NVIC_SystemReset();
};
