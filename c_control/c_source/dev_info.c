#include <stdio.h>

#include <stdarg.h>

#include "CommonType.h"

#include "skf.h"

#define USER_TYPE   1

//HANDLE hDev = NULL;
//HAPPLICATION hApplication = NULL;
//HCONTAINER hContainer = NULL;

// 连接 认证设备
int ConnectAndAuthDev1(char* uzDevName, HANDLE* phDev, char* devinfo)
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

	
    memcpy(devinfo, dev_info.SerialNumber, 32);
    memcpy(devinfo + 32, dev_info.Issuer, 64);

    //序列号
/*
    for(int i = 0; i < sizeof(dev_info.SerialNumber); i ++){
		printf("%c", dev_info.SerialNumber[i]);	
	}
	printf("=====%s\n", dev_info.SerialNumber);	
    //密码模块厂商信息
    for(int i = 0; i < sizeof(dev_info.Manufacturer); i ++){
		printf("%c", dev_info.Issuer[i]);	
	}
	printf("=====%s\n", dev_info.Issuer);
	printf("=====%s\n", dev_info.Manufacturer);
*/
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


void get_hw_code(char *devinfo)
{
	ULONG rv;
	BYTE ucHwCode[64] = {0};
	ULONG ulHwCodeLen = 64;
	char keylist[256] = {0};
	ULONG keylistLen = 256;
	char szDevName[256] = {0};
	ULONG ulDevNameLen = 8, ulEvent = 0;
    	HANDLE hDev = NULL;

	//enum device
	rv = SKF_EnumDev(TRUE, keylist, &keylistLen);
	if (rv != SAR_OK)
	{
		printf("SKF_EnumDev Wrong 0x%08X\n",rv);
		fflush(stdin);
		getchar();
		return;
	}
	printf("SKF_EnumDev OK\n",rv);

	//connect
	rv = SKF_ConnectDev(keylist, &hDev);
	if (rv != SAR_OK || hDev == NULL)
	{
		printf("SKF_ConnectDev Wrong\n");
		fflush(stdin);
		getchar();
		return;
	}
	printf("SKF_ConnectDev OK\n");
	//get hardware encode
	rv = SKFE_GetHwCode(hDev, ucHwCode,&ulHwCodeLen);
	if(SAR_OK != rv)
	{
		printf("SKFE_GetHwCode Wrong : 0x%08X\n",rv);
		fflush(stdin);
		getchar();
		return;
	}
	SKF_DisConnectDev(hDev);

    //密码模块ID
    memcpy(devinfo + 96, ucHwCode, 22);
    printf("%s\n",ucHwCode);
}

int get_devinfo(char *devinfo)
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
	//BYTE devinfo[64] = {0};








	

    HANDLE hAgreementKeyHandle1 = NULL, hAgreementKeyHandle2 = NULL;

	BYTE bCerText[2048] = {0};
	ULONG ulCerTextLen = 1024;
	BOOL bSignflag = FALSE;
    ULONG ulRetryCounter=0;

    rv = SKF_EnumDev(TRUE, uzDevList, &uDevListLen);

    // 设备
    p = uzDevList;
    // 连接设备并设备认证
    if (ConnectAndAuthDev1(p, &hDev1, devinfo) != 0)
    {
        printf("ConnectAndAuthDev1 Wrong. %s\n",p);
        fflush(stdin);
        getchar();
        return ;
    }



    get_hw_code(devinfo);



    //rv = SKF_DeleteApplication(hDev1, "ECCTestApp");
    SKF_DisConnectDev(hDev1);

}
