#include "easi.h"

const static uint8 Lwm2mResourceOperationRead = 1;
const static uint8 Lwm2mResourceOperationWrite = 2;
const static uint8 Lwm2mResourceOperationExecute = 4;

bool addInstance(uint16 objectID, uint16 instanceID);
int createRegisterContent(uint8 *output);
int readInstanceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint8 *output);
int readResourceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID, uint8 *output);
int writeInstanceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint8 *input, uint16 len);
int writeResourceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID, uint8 *input, uint16 len);
int executeResourceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID, uint8 *input, uint16 len);
bool setReadResourceOperation(uint16 objectID, uint16 instanceID, uint16 resourceID, void (*func)(Lwm2mTLV *tlv));
bool setWriteResourceOperation(uint16 objectID, uint16 instanceID, uint16 resourceID, void (*func)(Lwm2mTLV *tlv));
bool setExecuteResourceOperation(uint16 objectID, uint16 instanceID, uint16 resourceID, void (*func)(Lwm2mTLV *tlv));
int writeSecurityParams(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint8 *input, uint16 len);

void defaultOperation(Lwm2mTLV *tlv);
void setServerID(Lwm2mTLV *tlv);
void getServerID(Lwm2mTLV *tlv);

static uint8 serverID = 0;

void defaultOperation(Lwm2mTLV *tlv){};

void setServerID(Lwm2mTLV *tlv){
    serverID = (uint8)tlv->intValue;
}

void getServerID(Lwm2mTLV *tlv){
    tlv->intValue = serverID;
}

const static Lwm2mResource securityResources[] = { // Object ID = 0
    { 0, 0, Lwm2mResourceTypeString, NULL, NULL, NULL }, // LWM2M  Server URI
    { 1, 0, Lwm2mResourceTypeBoolean, NULL, NULL, NULL }, // Bootstrap-Server
    { 2, 0, Lwm2mResourceTypeInteger, NULL, NULL, NULL }, // Security Mode
    { 3, 0, Lwm2mResourceTypeOpaque, NULL, NULL, NULL }, // Public Key or Identity
    { 4, 0, Lwm2mResourceTypeOpaque, NULL, NULL, NULL }, // Server Public Key
    { 5, 0, Lwm2mResourceTypeOpaque, NULL, NULL, NULL }, // Secret Key
    { 6, 0, Lwm2mResourceTypeInteger, NULL, NULL, NULL }, // SMS Security Mode
    { 7, 0, Lwm2mResourceTypeOpaque, NULL, NULL, NULL }, // SMS Binding Key Parameters
    { 8, 0, Lwm2mResourceTypeOpaque, NULL, NULL, NULL }, // SMS Binding Secret Key(s)
    { 9, 0, Lwm2mResourceTypeString, NULL, NULL, NULL }, // LwM2M Server SMS Number
    { 10, 0, Lwm2mResourceTypeInteger, NULL, NULL, NULL }, // Short Server ID
    { 11, 0, Lwm2mResourceTypeInteger, NULL, NULL, NULL }, // Client Hold Off Time
    { 12, 0, Lwm2mResourceTypeInteger, NULL, NULL, NULL }, // Bootstrap-Server Account Timeout
};

const static Lwm2mResource serverResources[] = { // Object ID = 1
    { 0, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, getServerID, setServerID, NULL }, // Short Server ID
    { 1, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Lifetime
    { 2, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Default Minimum Period
    { 3, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Default Maximum Period
    { 4, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Disable
    { 5, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Disable Timeout
    { 6, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeBoolean, defaultOperation, defaultOperation, NULL }, // Notification Storing When Disabled or Offline
    { 7, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Binding
    { 8, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Registration Update Trigger
};

const static Lwm2mResource accessControlResources[] = { // Object ID = 2
    { 0, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Object ID
    { 1, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Object Instance ID
    { 2, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // ACL
    { 3, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Access Control Owner
};

const static Lwm2mResource deviceResources[] = { // Object ID = 3
    { 0, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Manufacturer
    { 1, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Model Number
    { 2, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Serial Number
    { 3, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Firmware Version
    { 4, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reboot
    { 5, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Factory Reset
    { 6, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Available Power Sources
    { 7, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Power Source Voltage
    { 8, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Power Source Current
    { 9, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Battery Level
    { 10, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Memory Free
    { 11, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Error Code
    { 12, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Error Code
    { 13, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeTime, defaultOperation, defaultOperation, NULL }, // Current Time
    { 14, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // UTC Offset
    { 15, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Timezone
    { 16, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Supported Binding and Modes
    { 17, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Device Type
    { 18, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Hardware Version
    { 19, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Software Version
    { 20, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Battery Status
    { 21, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Memory Total
    { 22, Lwm2mResourceOperationRead, Lwm2mResourceTypeObjlnk, defaultOperation, NULL, NULL }, // ExtDevInfo
};

const static Lwm2mResource connectivityMonitoringResources[] = { // Object ID = 4
    { 0, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Network Bearer
    { 1, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Available Network Bearer
    { 2, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Radio Signal Strength
    { 3, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Link Quality
    { 4, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // IP Addresses
    { 5, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Router IP Addresses
    { 6, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Link Utilization
    { 7, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // APN
    { 8, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Cell ID
    { 9, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // SMNC
    { 10, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL } // SMCC
};

const static Lwm2mResource firmwareUpdateResources[] = { // Object ID = 5
    { 0, Lwm2mResourceOperationWrite, Lwm2mResourceTypeOpaque, NULL, defaultOperation, NULL }, // Package
    { 1, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Package URI
    { 2, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Update
    { 3, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // State
    { 5, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Update Result
    { 6, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // PkgName
    { 7, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // PkgVersion
    { 8, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Firmware Update Protocol Support
    { 9, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL } // Firmware Update Delivery Method
};

const static Lwm2mResource locationResources[] = { // Object ID = 6
    { 0, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Latitude
    { 1, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Longitude
    { 2, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Altitude
    { 3, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Radius
    { 4, Lwm2mResourceOperationRead, Lwm2mResourceTypeOpaque, defaultOperation, NULL, NULL }, // Velocity
    { 5, Lwm2mResourceOperationRead, Lwm2mResourceTypeTime, defaultOperation, NULL, NULL }, // Timestamp
    { 6, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL } // Speed
};

const static Lwm2mResource connectivityStatisticsResources[] = { // Object ID = 7
    { 0, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // SMS Tx Counter
    { 1, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // SMS Rx Counter
    { 2, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Tx Data
    { 3, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Rx Data
    { 4, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Max Message Size
    { 5, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Average Message Size
    { 6, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Start
    { 7, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Stop
    { 8, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL } // Collection Period
};

const static Lwm2mResource lockWipeResources[] = { // Object ID = 8
    { 0, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // State
    { 1, Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, NULL, defaultOperation, NULL }, // Lock target
    { 2, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Wipe item
    { 3, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Wipe
    { 4, Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, NULL, defaultOperation, NULL }, // Wipe target
    { 5, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL } // Lock or Wipe Operation Result
};

const static Lwm2mResource softwareManagementResources[] = { // Object ID = 9
    { 0, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // PkgName
    { 1, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // PkgVersion
    { 2, Lwm2mResourceOperationWrite, Lwm2mResourceTypeOpaque, NULL, defaultOperation, NULL }, // Package
    { 3, Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, NULL, defaultOperation, NULL }, // Package URI
    { 4, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Install
    { 5, Lwm2mResourceOperationRead, Lwm2mResourceTypeObjlnk, defaultOperation, NULL, NULL }, // Checkpoint
    { 6, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Uninstall
    { 7, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Update State
    { 8, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeBoolean, defaultOperation, defaultOperation, NULL }, // Update Supported Objects
    { 9, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Update Result
    { 10, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Activate
    { 11, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Deactivate
    { 12, Lwm2mResourceOperationRead, Lwm2mResourceTypeBoolean, defaultOperation, NULL, NULL }, // Activation State
    { 13, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeObjlnk, defaultOperation, defaultOperation, NULL }, // Package Settings
    { 14, Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, NULL, defaultOperation, NULL }, // User Name
    { 15, Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, NULL, defaultOperation, NULL } // Password
};

const static Lwm2mResource digitalInputResources[] = { // Object ID = 3200
    { 5500, Lwm2mResourceOperationRead, Lwm2mResourceTypeBoolean, defaultOperation, NULL, NULL }, // Digital Input State
    { 5501, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Digital Input Counter
    { 5502, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeBoolean, defaultOperation, defaultOperation, NULL }, // Digital Input Polarity
    { 5503, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Digital Input Debounce
    { 5504, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Digital Input Edge Selection
    { 5505, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Digital Input Counter Reset
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
    { 5751, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Type
};

const static Lwm2mResource digitalOutputResources[] = { // Object ID = 3201
    { 5550, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeBoolean, defaultOperation, defaultOperation, NULL }, // Digital Output State
    { 5551, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeBoolean, defaultOperation, defaultOperation, NULL }, // Digital Output Polarity
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource analogInputResources[] = { // Object ID = 3202
    { 5600, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Analog Input Current Value
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
    { 5751, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Type
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
};

const static Lwm2mResource analogOutputResources[] = { // Object ID = 3203
    { 5650, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Analog Output Current Value
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
};

const static Lwm2mResource genericSensorResources[] = { // Object ID = 3300
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
    { 5751, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Type
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
};

const static Lwm2mResource illuminanceResources[] = { // Object ID = 3301
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
};

const static Lwm2mResource presenceResources[] = { // Object ID = 3302
    { 5500, Lwm2mResourceOperationRead, Lwm2mResourceTypeBoolean, defaultOperation, NULL, NULL }, // Digital Input State
    { 5501, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Digital Input Counter
    { 5505, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Digital Input Counter Reset
    { 5751, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Type
    { 5903, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Busy to Clear delay
    { 5904, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Clear to Busy delay
};

const static Lwm2mResource temperatureResources[] = { // Object ID = 3303
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
};

const static Lwm2mResource humidityResources[] = { // Object ID = 3304
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
};

const static Lwm2mResource powerMeasurementResources[] = { // Object ID = 3305
    { 5800, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Instantaneous active power
    { 5801, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured active power
    { 5802, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured active power
    { 5803, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range active power
    { 5804, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range active power
    { 5805, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Cumulative active power
    { 5806, Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, NULL, defaultOperation, NULL }, // Active Power Calibration
    { 5810, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Instantaneous reactive power
    { 5811, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured reactive power
    { 5812, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured reactive power
    { 5813, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range reactive power
    { 5814, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range reactive power
    { 5815, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Cumulative reactive power
    { 5816, Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, NULL, defaultOperation, NULL }, // Reactive Power Calibration
    { 5820, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Power factor
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5822, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Cumulative energy
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
};

const static Lwm2mResource actuationResources[] = { // Object ID = 3306
    { 5850, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeBoolean, defaultOperation, defaultOperation, NULL }, // On/Off
    { 5851, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Dimmer
    { 5852, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // On time
    { 5853, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Muti-state Output
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource setPointResources[] = { // Object ID = 3308
    { 5900, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Set Point Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5706, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Colour
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource loadControlResources[] = { // Object ID = 3310
    { 5823, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Event Identifier
    { 5824, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeTime, defaultOperation, defaultOperation, NULL }, // Start Time
    { 5825, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Duration In Min
    { 5826, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Criticality Level
    { 5827, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Avg Load AdjPct
    { 5828, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Duty Cycle
};

const static Lwm2mResource lightControlResources[] = { // Object ID = 3311
    { 5850, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeBoolean, defaultOperation, defaultOperation, NULL }, // On/Off
    { 5851, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Dimmer
    { 5852, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // On time
    { 5805, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Cumulative active power
    { 5820, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Power factor
    { 5706, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Colour
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource powerControlResources[] = { // Object ID = 3312
    { 5850, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeBoolean, defaultOperation, defaultOperation, NULL }, // On/Off
    { 5851, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Dimmer
    { 5852, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // On time
    { 5805, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Cumulative active power
    { 5820, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Power factor
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource accelerometerResources[] = { // Object ID = 3313
    { 5702, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // X Value
    { 5703, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Y Value
    { 5704, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Z Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
};

const static Lwm2mResource magnetometerResources[] = { // Object ID = 3314
    { 5702, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // X Value
    { 5703, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Y Value
    { 5704, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Z Value
    { 5705, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Compass Direction
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
};

const static Lwm2mResource barometerResources[] = { // Object ID = 3315
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
};

const static Lwm2mResource voltageResources[] = { // Object ID = 3316
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource currentResources[] = { // Object ID = 3317
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource frequencyResources[] = { // Object ID = 3318
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource depthResources[] = { // Object ID = 3319
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource percentageResources[] = { // Object ID = 3320
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource altitudeResources[] = { // Object ID = 3321
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource loadResources[] = { // Object ID = 3322
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource pressureResources[] = { // Object ID = 3323
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource loudnessResources[] = { // Object ID = 3324
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource concentrationResources[] = { // Object ID = 3325
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource acidityResources[] = { // Object ID = 3326
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource conductivityResources[] = { // Object ID = 3327
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource powerResources[] = { // Object ID = 3328
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource powerFactorResources[] = { // Object ID = 3329
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource distanceResources[] = { // Object ID = 3330
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource energyResources[] = { // Object ID = 3331
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5822, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Cumulative energy
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource directionResources[] = { // Object ID = 3332
    { 5705, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Compass Direction
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource timeResources[] = { // Object ID = 3333
    { 5506, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeTime, defaultOperation, defaultOperation, NULL }, // Current Time
    { 5507, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Fractional Time
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource gyrometerResources[] = { // Object ID = 3334
    { 5702, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // X Value
    { 5703, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Y Value
    { 5704, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Z Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5508, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min X Value
    { 5509, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max X Value
    { 5510, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Y Value
    { 5511, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Y Value
    { 5512, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Z Value
    { 5513, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Z Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource colourResources[] = { // Object ID = 3335
    { 5706, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Colour
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource location2Resources[] = { // Object ID = 3336
    { 5514, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Latitude
    { 5515, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Longitude
    { 5516, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Uncertainty
    { 5705, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Compass Direction
    { 5517, Lwm2mResourceOperationRead, Lwm2mResourceTypeOpaque, defaultOperation, NULL, NULL }, // Velocity
    { 5518, Lwm2mResourceOperationRead, Lwm2mResourceTypeTime, defaultOperation, NULL, NULL }, // Timestamp
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource positionerResources[] = { // Object ID = 3337
    { 5536, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Position
    { 5537, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Transition Time
    { 5538, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Remaining Time
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5519, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Limit
    { 5520, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Limit
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource buzzerResources[] = { // Object ID = 3338
    { 5850, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeBoolean, defaultOperation, defaultOperation, NULL }, // On/Off
    { 5548, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Level
    { 5521, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Delay Duration
    { 5525, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Minimum Off-time
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource audioClipResources[] = { // Object ID = 3339
    { 5522, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeOpaque, defaultOperation, defaultOperation, NULL }, // Clip
    { 5523, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Trigger
    { 5548, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Level
    { 5524, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Duration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource timerResources[] = { // Object ID = 3340
    { 5521, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Delay Duration
    { 5538, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Remaining Time
    { 5525, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Minimum Off-time
    { 5523, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Trigger
    { 5850, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeBoolean, defaultOperation, defaultOperation, NULL }, // On/Off
    { 5501, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Digital Input Counter
    { 5544, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Cumulative Time
    { 5543, Lwm2mResourceOperationRead, Lwm2mResourceTypeBoolean, defaultOperation, NULL, NULL }, // Digital State
    { 5534, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Counter
    { 5526, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Timer Mode
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource addressableTextDisplayResources[] = { // Object ID = 3341
    { 5527, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Text
    { 5528, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // X Coordinate
    { 5529, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Y Coordinate
    { 5545, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Max X Coordinate
    { 5546, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Max Y Coordinate
    { 5530, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Clear Display
    { 5548, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Level
    { 5531, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Contrast
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource onOffswitchResources[] = { // Object ID = 3342
    { 5500, Lwm2mResourceOperationRead, Lwm2mResourceTypeBoolean, defaultOperation, NULL, NULL }, // Digital Input State
    { 5501, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Digital Input Counter
    { 5852, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // On time
    { 5854, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Off Time
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource dimmerResources[] = { // Object ID = 3343
    { 5548, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Level
    { 5852, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // On time
    { 5854, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Off Time
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource upDownControlResources[] = { // Object ID = 3344
    { 5532, Lwm2mResourceOperationRead, Lwm2mResourceTypeBoolean, defaultOperation, NULL, NULL }, // Increase Input State
    { 5533, Lwm2mResourceOperationRead, Lwm2mResourceTypeBoolean, defaultOperation, NULL, NULL }, // Decrease Input State
    { 5541, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Up Counter
    { 5542, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeInteger, defaultOperation, defaultOperation, NULL }, // Down Counter
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource multipleAxisJoystickResources[] = { // Object ID = 3345
    { 5500, Lwm2mResourceOperationRead, Lwm2mResourceTypeBoolean, defaultOperation, NULL, NULL }, // Digital Input State
    { 5501, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Digital Input Counter
    { 5702, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // X Value
    { 5703, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Y Value
    { 5704, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Z Value
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource rateResources[] = { // Object ID = 3346
    { 5700, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Sensor Value
    { 5701, Lwm2mResourceOperationRead, Lwm2mResourceTypeString, defaultOperation, NULL, NULL }, // Sensor Units
    { 5601, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Measured Value
    { 5602, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Measured Value
    { 5603, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Min Range Value
    { 5604, Lwm2mResourceOperationRead, Lwm2mResourceTypeFloat, defaultOperation, NULL, NULL }, // Max Range Value
    { 5605, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Reset Min and Max Measured Values
    { 5821, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Current Calibration
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource pushbuttonResources[] = { // Object ID = 3347
    { 5500, Lwm2mResourceOperationRead, Lwm2mResourceTypeBoolean, defaultOperation, NULL, NULL }, // Digital Input State
    { 5501, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Digital Input Counter
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource multiStateSelectorResources[] = { // Object ID = 3348
    { 5547, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Multi-state Input
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource bitmapResources[] = { // Object ID = 3349
    { 5910, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Bitmap Input
    { 5911, Lwm2mResourceOperationExecute, Lwm2mResourceTypeNone, NULL, NULL, defaultOperation }, // Bitmap Input Reset
    { 5912, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Element Description
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mResource stopwatchResources[] = { // Object ID = 3350
    { 5544, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeFloat, defaultOperation, defaultOperation, NULL }, // Cumulative Time
    { 5850, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeBoolean, defaultOperation, defaultOperation, NULL }, // On/Off
    { 5501, Lwm2mResourceOperationRead, Lwm2mResourceTypeInteger, defaultOperation, NULL, NULL }, // Digital Input Counter
    { 5750, Lwm2mResourceOperationRead | Lwm2mResourceOperationWrite, Lwm2mResourceTypeString, defaultOperation, defaultOperation, NULL }, // Application Type
};

const static Lwm2mObjectTemplate lwm2mObjectTemplates[] = {
    { 0, &securityResources[0], sizeof(securityResources) },
    { 1, &serverResources[0], sizeof(serverResources) },
    { 2, &accessControlResources[0], sizeof(accessControlResources) },
    { 3, &deviceResources[0], sizeof(deviceResources) },
    { 4, &connectivityMonitoringResources[0], sizeof(connectivityMonitoringResources) },
    { 5, &firmwareUpdateResources[0], sizeof(firmwareUpdateResources) },
    { 6, &locationResources[0], sizeof(locationResources) },
    { 7, &connectivityStatisticsResources[0], sizeof(connectivityStatisticsResources) },
    { 8, &lockWipeResources[0], sizeof(lockWipeResources) },
    { 9, &softwareManagementResources[0], sizeof(softwareManagementResources) },
    { 3200, &digitalInputResources[0], sizeof(digitalInputResources) },
    { 3201, &digitalOutputResources[0], sizeof(digitalOutputResources) },
    { 3202, &analogInputResources[0], sizeof(analogInputResources) },
    { 3203, &analogOutputResources[0], sizeof(analogOutputResources) },
    { 3300, &genericSensorResources[0], sizeof(genericSensorResources) },
    { 3301, &illuminanceResources[0], sizeof(illuminanceResources) },
    { 3302, &presenceResources[0], sizeof(presenceResources) },
    { 3303, &temperatureResources[0], sizeof(temperatureResources) },
    { 3304, &humidityResources[0], sizeof(humidityResources) },
    { 3305, &powerMeasurementResources[0], sizeof(powerMeasurementResources) },
    { 3306, &actuationResources[0], sizeof(actuationResources) },
    { 3308, &setPointResources[0], sizeof(setPointResources) },
    { 3310, &loadControlResources[0], sizeof(loadControlResources) },
    { 3311, &lightControlResources[0], sizeof(lightControlResources) },
    { 3312, &powerControlResources[0], sizeof(powerControlResources) },
    { 3313, &accelerometerResources[0], sizeof(accelerometerResources) },
    { 3314, &magnetometerResources[0], sizeof(magnetometerResources) },
    { 3315, &barometerResources[0], sizeof(barometerResources) },
    { 3316, &voltageResources[0], sizeof(voltageResources) },
    { 3317, &currentResources[0], sizeof(currentResources) },
    { 3318, &frequencyResources[0], sizeof(frequencyResources) },
    { 3319, &depthResources[0], sizeof(depthResources) },
    { 3320, &percentageResources[0], sizeof(percentageResources) },
    { 3321, &altitudeResources[0], sizeof(altitudeResources) },
    { 3322, &loadResources[0], sizeof(loadResources) },
    { 3323, &pressureResources[0], sizeof(pressureResources) },
    { 3324, &loudnessResources[0], sizeof(loudnessResources) },
    { 3325, &concentrationResources[0], sizeof(concentrationResources) },
    { 3326, &acidityResources[0], sizeof(acidityResources) },
    { 3327, &conductivityResources[0], sizeof(conductivityResources) },
    { 3328, &powerResources[0], sizeof(powerResources) },
    { 3329, &powerFactorResources[0], sizeof(powerFactorResources) },
    { 3330, &distanceResources[0], sizeof(distanceResources) },
    { 3331, &energyResources[0], sizeof(energyResources) },
    { 3332, &directionResources[0], sizeof(directionResources) },
    { 3333, &timeResources[0], sizeof(timeResources) },
    { 3334, &gyrometerResources[0], sizeof(gyrometerResources) },
    { 3335, &colourResources[0], sizeof(colourResources) },
    { 3336, &location2Resources[0], sizeof(location2Resources) },
    { 3337, &positionerResources[0], sizeof(positionerResources) },
    { 3338, &buzzerResources[0], sizeof(buzzerResources) },
    { 3339, &audioClipResources[0], sizeof(audioClipResources) },
    { 3340, &timerResources[0], sizeof(timerResources) },
    { 3341, &addressableTextDisplayResources[0], sizeof(addressableTextDisplayResources) },
    { 3342, &onOffswitchResources[0], sizeof(onOffswitchResources) },
    { 3343, &dimmerResources[0], sizeof(dimmerResources) },
    { 3344, &upDownControlResources[0], sizeof(upDownControlResources) },
    { 3345, &multipleAxisJoystickResources[0], sizeof(multipleAxisJoystickResources) },
    { 3346, &rateResources[0], sizeof(rateResources) },
    { 3347, &pushbuttonResources[0], sizeof(pushbuttonResources) },
    { 3348, &multiStateSelectorResources[0], sizeof(multiStateSelectorResources) },
    { 3349, &bitmapResources[0], sizeof(bitmapResources) },
    { 3350, &stopwatchResources[0], sizeof(stopwatchResources) },
};

static Lwm2mInstanceList *lwm2mInstanceList;

// サーバーオブジェクトをセットする
void initInstance(){
    Lwm2mResource *resources = (Lwm2mResource *)malloc(sizeof(serverResources));
    memcpy(resources, serverResources, sizeof(serverResources));

    Lwm2mInstance *instance = (Lwm2mInstance *)malloc(sizeof(Lwm2mInstance));
    instance->objectID = 1;
    instance->instanceID = 0;
    instance->resources = resources;
    instance->resourceLen = sizeof(serverResources) / sizeof(Lwm2mResource);

    lwm2mInstanceList = (Lwm2mInstanceList *)malloc(sizeof(Lwm2mInstanceList));
    lwm2mInstanceList->instance = instance;
    lwm2mInstanceList->next = NULL;
}

bool addInstance(uint16 objectID, uint16 instanceID){
    Lwm2mInstanceList *list = lwm2mInstanceList;
    while (list->next != NULL){
        list = list->next;
    }

    Lwm2mObjectTemplate objectTemplate;
    bool found = false;
    for (int i = 0; i < sizeof(lwm2mObjectTemplates) / sizeof(Lwm2mObjectTemplate); i++){
        objectTemplate = lwm2mObjectTemplates[i];
        if (objectTemplate.objectID == objectID){
            found = true;
            break;
        }
    }

    if (!found){
        // Object Not Found
        return false;
    }

    Lwm2mResource *resources = (Lwm2mResource *)malloc(objectTemplate.size);
    memcpy(resources, objectTemplate.resources, objectTemplate.size);

    Lwm2mInstance *instance = (Lwm2mInstance *)malloc(sizeof(Lwm2mInstance));
    instance->objectID = objectID;
    instance->instanceID = instanceID;
    instance->resources = resources;
    instance->resourceLen = objectTemplate.size / sizeof(Lwm2mResource);

    Lwm2mInstanceList *createdList = (Lwm2mInstanceList *)malloc(sizeof(Lwm2mInstanceList));
    createdList->instance = instance;
    createdList->next = NULL;
    list->next = createdList;

    return true;
}

int createRegisterContent(uint8 *output){
    char buf[1024];
    strcpy(buf, "</>;rt=\"oma.lwm2m\";ct=11543");
    Lwm2mInstanceList *list = lwm2mInstanceList;
    while (true){
        Lwm2mInstance *instance = list->instance;
        char element[16];
        sprintf(element, ",</%u/%u>", instance->objectID, instance->instanceID);
        strcat(buf, element);
        if (list->next == NULL){
            break;
        } else {
            list = list->next;
        }
    }

    int len = strlen(buf);
    memcpy(&output[0], buf, len);
    return len;
}


// 処理したバイト数合計を返す。処理できないリソースは無視する。
int readInstanceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint8 *output){
    int index = 0;
    Lwm2mInstanceList *list = lwm2mInstanceList;
    while (true){
        Lwm2mInstance *instance = list->instance;
        if (instance->objectID == objectID && instance->instanceID == instanceID){
            for (int i = 0; i < instance->resourceLen; i++){
                Lwm2mResource resource = instance->resources[i];
                if (resource.operation & Lwm2mResourceOperationRead){
                    Lwm2mTLV tlv;
                    lwm2mTLVInit(&tlv, Lwm2mTLVTypeResouce, resource.type, resource.id);
                    resource.read(&tlv);
                    index += lwm2mTLVSerialize(&tlv, &output[index]);
                }
            }
            break;
        }

        if (list->next == NULL){
            break;
        } else {
            list = list->next;
        }
    } 
    return index;
}

// 処理できたら処理したバイト数を、扱えない場合は負のCoapCodeを返す
int readResourceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID, uint8 *output){
    int index = 0;
    Lwm2mInstanceList *list = lwm2mInstanceList;
    while (true){
        Lwm2mInstance *instance = list->instance;
        if (instance->objectID == objectID && instance->instanceID == instanceID){
            for (int i = 0; i < instance->resourceLen; i++){
                if (instance->resources[i].id == resourceID){
                    Lwm2mResource resource = instance->resources[i];
                    if (resource.operation & Lwm2mResourceOperationRead){
                        Lwm2mTLV tlv;
                        lwm2mTLVInit(&tlv, Lwm2mTLVTypeResouce, resource.type, resource.id);
                        resource.read(&tlv);
                        index += lwm2mTLVSerialize(&tlv, &output[0]);
                        return index;
                    } else {
                        // Read OperationのないResource
                        return -CoapCodeMethodNotAllowed;
                    }
                }
            }
        }

        if (list->next == NULL){
            break;
        } else {
            list = list->next;
        }
    }
    // 対象Resourceが存在しない
    return -CoapCodeNotFound;
}

// 処理したバイト数合計を返す。処理できないリソースは無視する。
int writeInstanceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint8 *input, uint16 len){
    if (objectID == 0){
        // objectID = 0はセキュリティパラメータの設定であり、通常のリソースのようには扱わない
        return writeSecurityParams(lwm2m, objectID, instanceID, input, len);
    }

    int index = 0;
    Lwm2mInstanceList *list = lwm2mInstanceList;
    while (true){
        Lwm2mInstance *instance = list->instance;
        if (instance->objectID == objectID && instance->instanceID == instanceID){
            int i = 0;
            while (index < len) {
                uint16 id = lwm2mTLVGetID(&input[index]);
                for (; i < instance->resourceLen; i++){
                    Lwm2mResource resource = instance->resources[i];
                    if (resource.id == id){
                         Lwm2mTLV tlv;
                        lwm2mTLVInit(&tlv, Lwm2mTLVTypeResouce, resource.type, id);
                        index += lwm2mTLVDeserialize(&tlv, &input[index]);
                        if ((!lwm2m->bootstraped && resource.write != NULL) || (resource.operation & Lwm2mResourceOperationWrite)){
                            resource.write(&tlv);
                        }
                        break;
                    }
                }
                i++;
            }
            break;
        }

        if (list->next == NULL){
            break;
        } else {
            list = list->next;
        }
    }
    return index;
}

// 処理できたら処理したバイト数を、扱えない場合は負のCoapCodeを返す
int writeResourceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID, uint8 *input, uint16 len){
    int index = 0;
    Lwm2mInstanceList *list = lwm2mInstanceList;
    while (true){
        Lwm2mInstance *instance = list->instance;
        if (instance->objectID == objectID && instance->instanceID == instanceID){
            for (int i = 0; i < instance->resourceLen; i++){
                if (instance->resources[i].id == resourceID){
                    Lwm2mResource resource = instance->resources[i];
                    Lwm2mTLV tlv;
                    lwm2mTLVInit(&tlv, Lwm2mTLVTypeResouce, resource.type, resource.id);
                    index += lwm2mTLVDeserialize(&tlv, input);
                    if ((!lwm2m->bootstraped && resource.write != NULL) || (resource.operation & Lwm2mResourceOperationWrite)){
                        resource.write(&tlv);
                        return index;
                    } else {
                        // Write OperationのないResource
                        return -CoapCodeMethodNotAllowed;
                    }
                }
            }
        }

        if (list->next == NULL){
            break;
        } else {
            list = list->next;
        }
    }
    // 対象Resourceが存在しない
    return -CoapCodeNotFound;
}

// 処理できたら処理したバイト数を、扱えない場合は負のCoapCodeを返す
int executeResourceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID, uint8 *input, uint16 len){
    Lwm2mInstanceList *list = lwm2mInstanceList;
    while (true){
        Lwm2mInstance *instance = list->instance;
        if (instance->objectID == objectID && instance->instanceID == instanceID){
            for (int i = 0; i < instance->resourceLen; i++){
                if (instance->resources[i].id == resourceID){
                    Lwm2mResource resource = instance->resources[i];
                    // Executeの場合はTLVではなく単なるバイト列が送られるが、
                    // 同じシグニチャのハンドラで扱えるようTLVのOpaqueとして扱えるようにする
                    Lwm2mTLV tlv;
                    lwm2mTLVInit(&tlv, Lwm2mTLVTypeResouce, resource.type, resource.id);
                    if (len > 0){
                        memcpy(&tlv.bytesValue[0], &input[0], len);
                        tlv.bytesLen = len;
                    }
                    if (resource.operation & Lwm2mResourceOperationExecute){
                        resource.execute(&tlv);
                        return len;
                    } else {
                        // Execute OperationのないResource
                        return -CoapCodeMethodNotAllowed;
                    }
                }
            }
        }

        if (list->next == NULL){
            break;
        } else {
            list = list->next;
        }
    }
    // 対象Resourceが存在しない
    return -CoapCodeNotFound;
}

bool setReadResourceOperation(uint16 objectID, uint16 instanceID, uint16 resourceID, void (*func)(Lwm2mTLV *tlv)){
    Lwm2mInstanceList *list = lwm2mInstanceList;
    while (true){
        Lwm2mInstance *instance = list->instance;
        if (instance->objectID == objectID && instance->instanceID == instanceID){
            for (int j = 0; j < instance->resourceLen; j++){
                if (instance->resources[j].id == resourceID){
                    instance->resources[j].read = func;
                    return true;
                }
            }
            break;
        }

        if (list->next == NULL){
            break;
        } else {
            list = list->next;
        }
    }

    return false;
}

bool setWriteResourceOperation(uint16 objectID, uint16 instanceID, uint16 resourceID, void (*func)(Lwm2mTLV *tlv)){
    Lwm2mInstanceList *list = lwm2mInstanceList;
    while (true){
        Lwm2mInstance *instance = list->instance;
        if (instance->objectID == objectID && instance->instanceID == instanceID){
            for (int j = 0; j < instance->resourceLen; j++){
                if (instance->resources[j].id == resourceID){
                    instance->resources[j].write = func;
                    return true;
                }
            }
            break;
        }

        if (list->next == NULL){
            break;
        } else {
            list = list->next;
        }
    }

    return false;
}

bool setExecuteResourceOperation(uint16 objectID, uint16 instanceID, uint16 resourceID, void (*func)(Lwm2mTLV *tlv)){
    Lwm2mInstanceList *list = lwm2mInstanceList;
    while (true){
        Lwm2mInstance *instance = list->instance;
        if (instance->objectID == objectID && instance->instanceID == instanceID){
            for (int j = 0; j < instance->resourceLen; j++){
                if (instance->resources[j].id == resourceID){
                    instance->resources[j].execute = func;
                    return true;
                }
            }
            break;
        }

        if (list->next == NULL){
            break;
        } else {
            list = list->next;
        }
    }

    return false;
}

int writeSecurityParams(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint8 *input, uint16 len){
    uint16 index = 0;
    while (index < len) {
        uint16 id = lwm2mTLVGetID(&input[index]);
        int i = 0;
        for (; i < sizeof(securityResources) / sizeof(Lwm2mResource); i++){
            if (securityResources[i].id == id){
                Lwm2mTLV tlv;
                lwm2mTLVInit(&tlv, Lwm2mTLVTypeResouce, securityResources[i].type, id);
                index += lwm2mTLVDeserialize(&tlv, &input[index]);

                if (objectID == 0 && instanceID == 1 && id == 3){
                    // デバイスID
                    memcpy(lwm2m->identity, tlv.bytesValue, tlv.bytesLen);
                    lwm2m->identity[tlv.bytesLen] = 0;
                } else if (objectID == 0 && instanceID == 1 && id == 5){
                    // PSK
                    memcpy(lwm2m->psk, tlv.bytesValue, tlv.bytesLen);
                }
                break;
            }
        }
        i++;
    }
    return index;
}