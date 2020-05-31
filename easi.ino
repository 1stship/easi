#include "easi.h"

#define EASI_WIO_LTE
// #define EASI_M5_STACK
#define EASI_VERSION "V1.1.0"

Lwm2m lwm2m;
#ifdef EASI_WIO_LTE
#include <WioLTEforArduino.h>
WioLTE wio;
#endif
#ifdef EASI_M5_STACK
#include <M5Stack.h>
#define TINY_GSM_MODEM_UBLOX
#include <TinyGsmClient.h>
TinyGsm modem(Serial2);
#endif

void setup() {
  // 初期化
#ifdef EASI_WIO_LTE
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
#endif
#ifdef EASI_M5_STACK
  Serial.begin(115200);
  M5.begin();
  M5.Lcd.clear(BLACK);
  M5.Lcd.setTextColor(WHITE);
  M5.Lcd.println(F("M5Stack + 3G Module"));

  M5.Lcd.print(F("Modem Initialize..."));
  Serial2.begin(115200, SERIAL_8N1, 16, 17);
  modem.restart();
  M5.Lcd.println(F("done"));

  M5.Lcd.print(F("Connecting 3G..."));
  while (!modem.waitForNetwork()) M5.Lcd.print(".");
  M5.Lcd.println(F("done"));

  M5.Lcd.print(F("Connecting SORACOM..."));
  modem.gprsConnect("soracom.io", "sora", "sora");
  M5.Lcd.println(F("done"));

  M5.Lcd.print(F("Checking Network..."));
  while (!modem.isNetworkConnected()) M5.Lcd.print(".");
  M5.Lcd.println(F("OK"));

  delay(2000);
#endif

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
  setReadResourceOperation   (   3, 0,    2, &getSerial);      // READ    /3/0/2       でgetSerialが呼ばれるよう設定
  setWriteResourceOperation  (3311, 0, 5850, &turnOnOffLight); // WRITE   /3311/0/5850 でturnOnOffLightが呼ばれるよう設定
  setExecuteResourceOperation(   3, 0,    4, &reboot);         // EXECUTE /3/0/3       でrebootが呼ばれるよう設定

  // ブートストラップ(接続情報取得)実行
  // 成功するまで繰り返す
#ifdef EASI_M5_STACK
  M5.Lcd.println(F("LwM2M Bootstraping..."));
#endif
  while (!lwm2mBootstrap(&lwm2m)){ }
#ifdef EASI_M5_STACK
  M5.Lcd.println(F("OK"));
  M5.Lcd.println(F("easi version " EASI_VERSION " is ready to play!"));
#endif
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
void turnOnOffLight(Lwm2mTLV *tlv){
#ifdef EASI_WIO_LTE
  if (tlv->intValue){
    wio.LedSetRGB(255, 0, 0);
  } else {
    wio.LedSetRGB(0, 0, 0);
  }
#endif
#ifdef EASI_M5_STACK
  if (tlv->intValue){
    M5.Lcd.fillScreen(TFT_WHITE);
  } else {
    M5.Lcd.fillScreen(TFT_BLACK);
  }
#endif
};

// EXECUTEの場合、
// パラメータはOpaqueと同じ形式で渡す(使わなくてもよい)
void reboot(Lwm2mTLV *tlv){
#ifdef EASI_WIO_LTE
  NVIC_SystemReset();
#endif
#ifdef EASI_M5_STACK
  esp_restart();
#endif
};