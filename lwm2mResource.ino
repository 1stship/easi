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
    { 9, &softwareManagementResources[0], sizeof(softwareManagementResources) }
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
