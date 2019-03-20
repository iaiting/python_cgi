#include <stdio.h>

#include <stdarg.h>

#include "CommonType.h"

#include "skf.h"

#define USER_TYPE   1

/*
HANDLE hDev = NULL;
HAPPLICATION hApplication = NULL;
HCONTAINER hContainer = NULL;
*/

// 标准数据 这是ECC密钥协商所需的标准数据
unsigned char X_sm2[] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x3C,0xB5,0x72,0xF0,0xD5,0x48,0xD4,0x89,0xA8,0xDB,0x97,0xB7,0x37,0xE0,0xAC,0x63,
    0x36,0x7F,0x10,0xE8,0x06,0xD1,0xFA,0xF3,0x1D,0x7C,0x0D,0x09,0xEF,0xBF,0x82,0x4F
};
unsigned char Y_sm2[] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xA2,0x77,0x85,0x1E,0xB1,0x1B,0x88,0xF5,0x97,0xCA,0xFB,0xBF,0x87,0xF8,0x62,0x55,
    0xFA,0xC4,0xE5,0xE0,0x21,0xF9,0xE6,0x5B,0x02,0xEA,0x5C,0xEA,0x78,0x10,0xBD,0x4A
};
unsigned char prikey_sm2[] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x5B,0x9A,0x69,0xF5,0x9B,0xA5,0xC1,0xB5,0xFA,0x88,0x7E,0x2D,0x32,0xE9,0xA0,0xA4,
    0x31,0x77,0x5C,0xB2,0xB1,0xFD,0xC1,0x31,0x78,0x29,0x67,0xF2,0xBE,0x38,0x08,0xA3
};
/*
// 连接 认证设备
int ConnectAndAuthDev(char* uzDevName, HANDLE* phDev)
{
    DWORD rv = 0;
    UCHAR KeyValue[16] = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};
    HANDLE hDev = NULL;
    DEVINFO dev_info;
    BYTE ucRandom[16] = {0};
    DWORD ulRandomLen = 16;
    HANDLE   hImportSessionKey = NULL;
    BLOCKCIPHERPARAM EncryptParam;
    UCHAR ucDevauth[16] = {0};
    ULONG ulDevAuth = 16;

    rv = SKF_ConnectDev(uzDevName, &hDev);
    if (SAR_OK != rv)
    {
        return -1;
    }
    *phDev = hDev;

    rv  = SKF_GetDevInfo(hDev, &dev_info);
    if (SAR_OK != rv)
    {
        return -1;
    }

    rv = SKF_GenRandom(hDev,ucRandom,ulRandomLen);
    if (SAR_OK != rv)
    {
        return -1;
    }

    rv = SKF_SetSymmKey(hDev,(UCHAR*)KeyValue,dev_info.DevAuthAlgId,&hImportSessionKey);
    if (SAR_OK != rv)
    {
        return -1;
    }

    EncryptParam.PaddingType = 0;
    EncryptParam.IVLen = 0;
    memset(EncryptParam.IV,0,32);
    rv = SKF_EncryptInit(hImportSessionKey,EncryptParam);
    if (SAR_OK != rv)
    {
        SKF_CloseHandle(hImportSessionKey);
        return -1;
    }

    rv = SKF_Encrypt(hImportSessionKey,ucRandom,sizeof(ucRandom),NULL,&ulDevAuth);
    rv = SKF_Encrypt(hImportSessionKey,ucRandom,sizeof(ucRandom),ucDevauth,&ulDevAuth);
    if (SAR_OK != rv)
    {
        SKF_CloseHandle(hImportSessionKey);
        return -1;
    }
    rv = SKF_DevAuth(hDev,ucDevauth,ulDevAuth);
    if (SAR_OK != rv)
    {
        SKF_CloseHandle(hImportSessionKey);
        return -1;
    }
    SKF_CloseHandle(hImportSessionKey);
    return 0;
}
*/
int eccpublickey(unsigned char *eccpubkey)
{
    DWORD rv = 0;
    HANDLE hDev1 = NULL;
    HANDLE hDev = NULL;
    char* p = NULL;
    char uzDevList[1280] = {0};
    ULONG uDevListLen = 1280;

    HAPPLICATION hApp1 = NULL;
    ULONG ulRetryTime = 0;
    HCONTAINER hContainer1 = NULL;
    ECCPUBLICKEYBLOB tSm2SignPubkeyBlob1 = {0}, tSm2EncryptPubkeyBlob1 = {0}, tSm2TmpPubkeyBlob1 = {0};
    ECCPUBLICKEYBLOB tSm2EncryptPubkeyBlob2 = {0}, tSm2TmpPubkeyBlob2 = {0};

    BYTE SymKey[16] = {0xAF,0x72,0xF6,0x68,0x95,0x6B,0xC2,0x98,0x73,0xD9,0x85,0x3A,0x4F,0xAB,0x12,0x28};
    ECCCIPHERBLOB* SymKeyCiper = (PECCCIPHERBLOB)malloc(5000);
    HANDLE hKHandle = NULL;
    BLOCKCIPHERPARAM EncParam = {0};
    BYTE EncData[256] = {0};
    ULONG EncDataLen = 256;
    ENVELOPEDKEYBLOB* EnvdKeyBlob = (PENVELOPEDKEYBLOB)malloc(5000);

    HANDLE hAgreementHandle1 = NULL;


	

    HANDLE hAgreementKeyHandle1 = NULL, hAgreementKeyHandle2 = NULL;

	BYTE bCerText[2048] = {0};
	ULONG ulCerTextLen = 1024;
	BOOL bSignflag = FALSE;
    ULONG ulRetryCounter=0;

    // 以下是ECC密钥协商模拟流程（发起方和响应方是同一个设备）

    // 发起方发起ECC密钥协商流程，产生协商数据
    // 响应方使用上述协商数据也产生一个协商数据并同时产生会话密钥
    // 发起方使用响应方产生的协商数据并同时产生与响应方一样的会话密钥

    rv = SKF_EnumDev(TRUE, uzDevList, &uDevListLen);

    // 设备
    p = uzDevList;
    // 连接设备并设备认证
    if (ConnectAndAuthDev(p, &hDev1) != 0)
    {
        printf("ConnectAndAuthDev Wrong. %s\n",p);
        fflush(stdin);
        getchar();
        return ;
    }
    //rv = SKF_DeleteApplication(hDev1, "ECCTestApp");
    hDev = hDev1; // clear_dev_app中里用的设备句柄是全局变量，故将设备的设备句柄赋值给它

    // 在设备里创建ECCTestApp应用
    rv = SKF_CreateApplication(hDev1, "ECCTestApp", "AdminPin", 5, "UserPin", 3, SECURE_ANYONE_ACCOUNT, &hApp1);
	if (rv == 167772204) {
		printf("open app\n");
	 	rv = SKF_OpenApplication(hDev1, "ECCTestApp", &hApp1);
	     if (rv != SAR_OK){
	        printf("SKF_OpenApplication Wrong. %0x\n",rv);
	        fflush(stdin);
	        getchar();
	        return ;
	    }
	}
    else if (rv != SAR_OK){
	printf("SKF_CreateApplication Wrong. %x\n",rv);
	fflush(stdin);
	getchar();
	return ;
    }



    // 在设备里的ECCTestApp应用下进行用户PIN码认证
    rv = SKF_VerifyPIN(hApp1, USER_TYPE, "UserPin", &ulRetryTime);
    if (rv != SAR_OK)
    {
        printf("SKF_VerifyPIN Wrong. %0x\n",rv);
        fflush(stdin);
        getchar();
        return ;
    }


    // 在设备里的ECCTestApp应用下创建ECCPubkeyContainer容器

    rv = SKF_CreateContainer(hApp1, "ECCPubkeyContainer", &hContainer1);
	if (rv == 167772215){
		printf("open container\n");
		rv = SKF_OpenContainer(hApp1, "ECCPubkeyContainer", &hContainer1);	
	}else if (rv != SAR_OK || hContainer1 == NULL)
    {
        printf("SKF_CreateContainer Wrong. %0x\n",rv);
        fflush(stdin);
        getchar();
        return ;
    }


    // 在设备里产生ECC公私钥对并输出公钥
    rv = SKF_GenECCKeyPair(hContainer1, SGD_SM2_1, &tSm2SignPubkeyBlob1);
    if (rv != SAR_OK)
    {
        printf("SKF_GenECCKeyPair Wrong. %s%0x\n",p, rv);
        fflush(stdin);
        getchar();
        return -1;
    }

    memcpy(eccpubkey, tSm2SignPubkeyBlob1.XCoordinate, 64);
    memcpy(eccpubkey + 64, tSm2SignPubkeyBlob1.YCoordinate, 64);
/*
    for(int i = 0; i < 128; i++){
	printf("%02x", eccpubkey[i]);
    }
    printf("\n");
    for(int i = 0; i < sizeof(tSm2SignPubkeyBlob1.YCoordinate); i++){
	printf("%02x", tSm2SignPubkeyBlob1.YCoordinate[i]);
    }
    printf("\n");
*/

    rv = SKF_CloseHandle(hAgreementKeyHandle1);
    rv = SKF_CloseContainer(hContainer1);
    rv = SKF_CloseApplication(hApp1);

    //rv = SKF_DeleteApplication(hDev1, "ECCTestApp");
    SKF_DisConnectDev(hDev1);
    return 0;

}
