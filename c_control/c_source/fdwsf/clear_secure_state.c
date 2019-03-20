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
int clear()
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
    //
    hDev = hDev1; // clear_dev_app中里用的设备句柄是全局变量，故将设备的设备句柄赋值给它


    rv = SKF_CloseHandle(hAgreementKeyHandle1);
    rv = SKF_CloseContainer(hContainer1);
    rv = SKF_CloseApplication(hApp1);
    rv = SKF_DeleteApplication(hDev1, "ECCTestApp");
    rv = SKF_ClearSecureState(hApp1);
    printf("clear data ok!\n");
    SKF_DisConnectDev(hDev1);

}
