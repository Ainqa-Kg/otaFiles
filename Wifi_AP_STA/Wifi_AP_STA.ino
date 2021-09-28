#include <ESP8266WiFi.h>
#include <ESPAsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <EEPROM.h>
#include <SPI.h>
#include <MFRC522.h>
#include <ESP8266HTTPClient.h>
#include <ArduinoJson.h>
#include <ESP8266httpUpdate.h>
#include <WiFiClientSecure.h>
#include <CertStoreBearSSL.h>
BearSSL::CertStore certStore;
#include <time.h>
#include <Arduino.h>

//---------RFID------------------------------
constexpr uint8_t RST_PIN = D3;// Configurable, see typical pin layout above
constexpr uint8_t SS_PIN = D4;
MFRC522 rfid(SS_PIN, RST_PIN); // Instance of the class
MFRC522::MIFARE_Key key;
String tag;

//-----EEPROM address definition-----------------
int addr_ssid = 0;         // ssid index
int addr_password = 30;    // password index

// Set to true to reset eeprom before to write something
#define RESET_EEPROM false

const String device_token_id  = "2c4f3c";
const String APid = "NodeMCU_" + device_token_id;
const String url = "http://192.168.1.5:8010";

const String FirmwareVer={"2.4"}; 
#define URL_fw_Version "/Ainqa-Kg/otaFiles/master/version.txt"
#define URL_fw_Bin "https://raw.githubusercontent.com/Ainqa-Kg/otaFiles/master/fw.bin"
const char* host = "raw.githubusercontent.com";
const int httpsPort = 443;

// DigiCert High Assurance EV Root CA
const char trustRoot[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIQAqxcJmoLQJuPC3nyrkYldzANBgkqhkiG9w0BAQUFADBs
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j
ZSBFViBSb290IENBMB4XDTA2MTExMDAwMDAwMFoXDTMxMTExMDAwMDAwMFowbDEL
MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2Ug
RVYgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbM5XPm
+9S75S0tMqbf5YE/yc0lSbZxKsPVlDRnogocsF9ppkCxxLeyj9CYpKlBWTrT3JTW
PNt0OKRKzE0lgvdKpVMSOO7zSW1xkX5jtqumX8OkhPhPYlG++MXs2ziS4wblCJEM
xChBVfvLWokVfnHoNb9Ncgk9vjo4UFt3MRuNs8ckRZqnrG0AFFoEt7oT61EKmEFB
Ik5lYYeBQVCmeVyJ3hlKV9Uu5l0cUyx+mM0aBhakaHPQNAQTXKFx01p8VdteZOE3
hzBWBOURtCmAEvF5OYiiAhF8J2a3iLd48soKqDirCmTCv2ZdlYTBoSUeh10aUAsg
EsxBu24LUTi4S8sCAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQF
MAMBAf8wHQYDVR0OBBYEFLE+w2kD+L9HAdSYJhoIAu9jZCvDMB8GA1UdIwQYMBaA
FLE+w2kD+L9HAdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQAcGgaX3Nec
nzyIZgYIVyHbIUf4KmeqvxgydkAQV8GK83rZEWWONfqe/EW1ntlMMUu4kehDLI6z
eM7b41N5cdblIZQB2lWHmiRk9opmzN6cN82oNLFpmyPInngiK3BD41VHMWEZ71jF
hS9OMPagMRYjyOfiZRYzy78aG6A9+MpeizGLYAiJLQwGXFK3xPkKmNEVX58Svnw2
Yzi9RKR/5CYrCsSXaQ3pjOLAEFe4yHYSkVXySGnYvCoCWw9E1CAx2/S6cCZdkGCe
vEsXCS+0yx5DaMkHJ8HSXPfqIbloEpw8nL+e/IBcm2PN7EeqJSdnoDfzAIJ9VNep
+OkuE6N36B9K
-----END CERTIFICATE-----
)EOF";
X509List cert(trustRoot);

extern const unsigned char caCert[] PROGMEM;
extern const unsigned int caCertLen;

const char* APssid = APid.c_str();
const char* APpassword = "1234567890";

String ssid = "";
String password = "";

AsyncWebServer server(80);

const char* PARAM_INPUT_1 = "SSID";
const char* PARAM_INPUT_2 = "PASSWORD";

// HTML web page to handle 3 input fields (input1, input2, input3)
const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE HTML><html><head>
  <title>WiFi Info. Input Form</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  </head><body>
  <form action="/get">
    Your_WiFi_SSID : <input type="text" name="SSID">
    Your_WiFi_Password : <input type="text" name="PASSWORD">
    <input type="submit" value="Submit">
  </form>
</body></html>)rawliteral";

void notFound(AsyncWebServerRequest *request) {
  request->send(404, "text/plain", "Not found");
}

  
void setup() {
  Serial.begin(115200);
  EEPROM.begin(512);
  delay(100);
  SPI.begin(); // Init SPI bus
  rfid.PCD_Init(); // Init MFRC522
  Serial.println("");
  WiFi.begin(ssid, password);
  configTime(3 * 3600, 0, "pool.ntp.org");
  FirmwareUpdate();
 
  // -------- In-case of erasing the EEPROM memory----------------
  if ( RESET_EEPROM ) {
    for (int i = 0; i < 512; i++) {
      EEPROM.write(i, 0);
    }
    EEPROM.commit();
    delay(500);
  }

  for (int k = addr_ssid; k < addr_ssid + 30; ++k) {
    ssid += char(EEPROM.read(k));
  }
  Serial.print("SSID from EEPROM : ");
  Serial.println(ssid);

  for (int l = addr_password; l < addr_password + 30; ++l) {
    password += char(EEPROM.read(l));
  }
  Serial.print("Password from EEPROM : ");
  Serial.print(password);

  // Mengatur WiFi ----------------------------------------------------------
  Serial.println();
  Serial.println("Configuring access point...");

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(APssid, APpassword);

  // Start the server -------------------------------------------------------
  server.begin();
  Serial.println("Server Started");

  // Print the IP address ---------------------------------------------------
  Serial.println(WiFi.softAPIP());

  // Send web page with input fields to client
  server.on("/", HTTP_GET, [](AsyncWebServerRequest * request) {
    request->send_P(200, "text/html", index_html);
  });

  // Send a GET request to <ESP_IP>/get?input1=<inputMessage>
  server.on("/get", HTTP_GET, [] (AsyncWebServerRequest * request) {
    String inputSSID;
    String inputPasswd;
    // GET input1 value on <ESP_IP>/get?input1=<inputMessage>
    if (request->hasParam(PARAM_INPUT_1) && request->hasParam(PARAM_INPUT_2)) {
      inputSSID = request->getParam(PARAM_INPUT_1)->value();
      inputPasswd = request->getParam(PARAM_INPUT_2)->value();
      if (ssid == "" && password == "" && WiFi.status() != WL_CONNECTED && inputSSID != "" && inputPasswd != "") {
        ssid = inputSSID;
        password = inputPasswd;

        for (int i = 0; i < ssid.length(); ++i) {
          EEPROM.write(addr_ssid + i, ssid[i]);
          // Serial.print(ssid[i]); Serial.print("");
        }

        for (int j = 0; j < password.length(); j++) {
          EEPROM.write(addr_password + j, password[j]);
          // Serial.print(password[j]); Serial.print("");
        }

        Serial.println("");
        if (EEPROM.commit()) {
          Serial.println("Data successfully committed");
        } else {
          Serial.println("ERROR! Data commit failed");
        }
      }
      else if (inputSSID != "" && inputPasswd != "") {
        WiFi.disconnect();
        Serial.println("WiFi disconnected.");
        ssid = inputSSID;
        password = inputPasswd;

        for (int i = 0; i < 512; i++) {
          EEPROM.write(i, 0);
        }
        EEPROM.commit();
        delay(500);

        for (int i = 0; i < ssid.length(); ++i) {
          EEPROM.write(addr_ssid + i, ssid[i]);
          // Serial.print(ssid[i]); Serial.print("");
        }

        for (int j = 0; j < password.length(); j++) {
          EEPROM.write(addr_password + j, password[j]);
          // Serial.print(password[j]); Serial.print("");
        }

        Serial.println("");
        if (EEPROM.commit()) {
          Serial.println("Data successfully committed");
        } else {
          Serial.println("ERROR! Data commit failed");
        }
        ssid = inputSSID;
        password = inputPasswd;
      }
    }
    if (inputSSID != "" && inputPasswd != "") {
      request->send(200, "text/html", "Entered SSID : " + inputSSID + "<br>Entered Passwod : " + inputPasswd +
                    "<br><a href=\"/\">Return to Home Page</a>");
    } else {
      request->send(200, "text/html", "<b>SSID or Password should not be empty.</b><br><a href=\"/\">Return to Home Page</a>");
    }
  });
  server.onNotFound(notFound);
  server.begin();
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "text/plain", "Hi! I am ESP8266.");
  });
}

void connectToWifi() {
  WiFi.begin(ssid.c_str(), password.c_str());
  Serial.println("Connecting...");
  if (WiFi.waitForConnectResult() != WL_CONNECTED) {
    Serial.println("WiFi Connection Failed!");
    return;
  }
  Serial.println("");
  // Print the IP address ---------------------------------------------------
  Serial.print("WiFi connected : ");
  Serial.println(WiFi.localIP());
}

void FirmwareUpdate(){
  delay(10000);
  //while ( WiFi.status() == WL_CONNECTED){
  Serial.println("Looking for update");  
  WiFiClientSecure client;
  client.setTrustAnchors(&cert);
  if (!client.connect(host, httpsPort)) {
    Serial.println("Connection failed");
    return;
  }
  client.print(String("GET ") + URL_fw_Version + " HTTP/1.1\r\n" +
               "Host: " + host + "\r\n" +
               "User-Agent: BuildFailureDetectorESP8266\r\n" +
               "Connection: close\r\n\r\n");
  while (client.connected()) {
    String line = client.readStringUntil('\n');
    if (line == "\r") {
      //Serial.println("Headers received");
      break;
    }
  }
  String payload = client.readStringUntil('\n');

  payload.trim();
  if(payload.equals(FirmwareVer) )
  {   
     Serial.println("Device already on latest firmware version"); 
  }
  else
  {
    Serial.println("New firmware detected");
    ESPhttpUpdate.setLedPin(LED_BUILTIN, LOW); 
    t_httpUpdate_return ret = ESPhttpUpdate.update(client, URL_fw_Bin);
        
    switch (ret) {
      case HTTP_UPDATE_FAILED:
        Serial.printf("HTTP_UPDATE_FAILD Error (%d): %s\n", ESPhttpUpdate.getLastError(), ESPhttpUpdate.getLastErrorString().c_str());
        break;

      case HTTP_UPDATE_NO_UPDATES:
        Serial.println("HTTP_UPDATE_NO_UPDATES");
        break;

      case HTTP_UPDATE_OK:
        Serial.println("HTTP_UPDATE_OK");
        break;
    } 
  }
  exit(0);
}

void loop() {
  if (ssid != "" && password != "" && WiFi.status() != WL_CONNECTED) {
    connectToWifi();
  }
  else {
    tag = "";
    if ( ! rfid.PICC_IsNewCardPresent())
      return;
    if (rfid.PICC_ReadCardSerial()) {
      for (byte i = 0; i < 4; i++) {
        tag += rfid.uid.uidByte[i];
      }
      Serial.println(tag);
      rfid.PICC_HaltA();
      rfid.PCD_StopCrypto1();

      DynamicJsonBuffer jBuffer;
      JsonObject& data = jBuffer.createObject();
      data["readerId"] = device_token_id;
      data["tagCode"] = tag;

      char JSONmessageBuffer[300];
      data.prettyPrintTo(JSONmessageBuffer, sizeof(JSONmessageBuffer));
      Serial.println(JSONmessageBuffer);
      data.prettyPrintTo(Serial);
      Serial.println();
      HTTPClient http;    //Declare object of class HTTPClient
      WiFiClient client;
      http.begin(client, url + "/upsertData");
      http.addHeader("Content-Type", "application/json");
      int httpCode = http.POST(JSONmessageBuffer);   //Send the request
      String payload = http.getString();
      Serial.println(httpCode);   //Print HTTP return code
      Serial.println(payload);    //Print request response payload
      Serial.println(FirmwareVer);
      //http.end();          
    }
  }
}
