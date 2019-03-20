#include <stdio.h>
#include <string.h>
#include "CommonType.h"
#include "skf.h"
#include "alg_performances.h"


#ifdef LINUX
#include <malloc.h>
#include <sys/time.h>
#endif


#ifndef LINUX
LARGE_INTEGER begintime;
LARGE_INTEGER endtime;
#else
struct timeval begintime;
struct timeval endtime; 
struct timezone  tz;
#endif 

#ifndef LINUX
void CallSpeed(LARGE_INTEGER begin ,LARGE_INTEGER end, int datalen , 
	char* Alg, char * mode)
{
	double time = 0.0;
	LARGE_INTEGER uFreq;
	QueryPerformanceFrequency(&uFreq);
	time = (end.QuadPart - begin.QuadPart) * 1.0 / uFreq.QuadPart;	//s

	if (datalen == 0)
	{
		PrintMsg("time = %.4f s\n", time);
		PrintMsg("%s %s average speed = %.3f 次/s\n\n",Alg,mode,1.0/time);
	}
	else
	{
		PrintMsg("data len  = %d byte\n",datalen);
		PrintMsg("time = %.4f s\n", time);
		PrintMsg("%s %s average speed = %.3f KB/s\n\n",Alg,mode,datalen/time/1024);
	}
}
#else
void CallSpeed(struct timeval begin ,struct timeval end, int datalen , 
	char * Alg, char * mode)
{
	float time  = 0;
	float sec = 0;
	float usec = 0;

	sec = end.tv_sec - begin.tv_sec;
	if(end.tv_usec - begin.tv_usec > 0)
	{
		usec = end.tv_usec - begin.tv_usec; 
	}
	else
	{
		usec = 1000000 +  end.tv_usec - begin.tv_usec;      
		if(sec > 0)
			sec-=1;
	}
	time = sec * 1000 +  usec / 1000;

	if (datalen == 0)
	{
		time = time/1000;
		PrintMsg("time = %.4f s\n", time);
		PrintMsg("%s %s average speed = %.3f times/s\n\n",Alg,mode,1.0/time);
	}
	else
	{
		PrintMsg("data len  = %d byte\n",datalen);
		PrintMsg("time = %f ms\n", time);
		PrintMsg("%s %s average speed = %.3fKBp/s\n\n",Alg,mode,datalen / time);
	}
}
#endif

void GetBeginTime(void* BeginTime)
{
#ifndef LINUX
	QueryPerformanceCounter((LARGE_INTEGER*)BeginTime);
#else
	gettimeofday((struct timeval*)BeginTime, NULL);
#endif
}
void GetEndTime(void* EndTime)
{
#ifndef LINUX
	QueryPerformanceCounter((LARGE_INTEGER*)EndTime);
#else
	gettimeofday((struct timeval*)EndTime, NULL);
#endif
}

UCHAR data[] = {
	0x7c,0x85,0x34,0xa2,0xcf,0x3c,0x7a,0xb9,0x3b,0xf8,0xf5,0x07,0xa1,0xe3,0xe8,0x39,0x15,0x73,0xa7,0xa2,0x7a,0x22,0x8f,0xf4,0x91,0x66,0x51,0x8d,0x98,0x01,0x4a,0xcc,0x5b,0x65,0xb1,0xa5,0x4d,0x90,0x13,0x66,0x3b,0xf8,0xf5,0x07,0x83,0x74,0x9e,0xad,0x47,0x3d,0x10,0x78,0x15,0x73,0xa7,0xa2,0x5e,0xad,0x16,0x3c,0x83,0x74,0x9e,0xad,0x54,0x3f,0x0a,0x65,0x1e,0x92,0xc2,0x3a,0xf8,0xf5,0x07,0x7c,0xf9,0xd0,0xe3,0xd3,0x0d,0x54,0x0e,0xb2,0x66,0xa4,0x53,0x1f,0xeb,0x8f,0x4e,0xf5,0xd8,0xb8,0x9d,0x28,0x0f,0x6e,0x6e,0x83,0x79,0xcb,0x6a,0x8c,0x73,0x8c,0xb1,0xa1,0xa0,0x58,0xda,0x4c,0x11,0xb0,0x44,0x6a,0x30,0xdf,0x4f,0xa2,0xb3,0x3d,0xa1,0xfd,0x4e,0x64,0x42,0xc1,0xa5,0x5a,0x0b,0x6a,0x06,0xd5,0xae,0x07,0x54,0x83,0xb8,0xe7,0xa6,0x66,0x67,0x9b,0xa4,0x3b,0x1b,0xfc,0x14,0x96,0x54,0xcc,0x54,0x83,0xb8,0xe7,0xfd,0xfe,0xb8,0xf4,0xd3,0x93,0x17,0x62,0xd1,0xfe,0x16,0x9b,0x93,0xd2,0x13,0xcf,0xbf,0xdf,0xeb,0x8f,0xe3,0x85,0x3e,0x10,0x45,0xb6,0x5b,0x1a,0x14,0x96,0x54,0xcc,0x04,0x0b,0x6c,0xbd,0xf8,0xf5,0x07,0x7c,0xf7,0x50,0x0a,0xa8,0x89,0xcc,0xda,0x81,0xbd,0x79,0x66,0x72,0x1c,0xa2,0x0b,0x4e,0x6c,0x16,0x91,0xc0,0x04,0x0b,0x6c,0xbd,0x20,0xe9,0x6a,0x52,0xcb,0xcd,0xb0,0x4a,0x4b,0x49,0x9d,0xa2,0x7c,0x11,0x84,0xc7,0x97,0x9d,0xa1,0xe9,0xe1,0x44,0xd4,0xe4,0xae,0x68,0x29,0x8a,0xdf,0xeb,0x8f,0x4e,0x50,0xfc,0x6a,0x69,0x24,0xa2,0x39,0xe1,0x9b,0xe7,0xb0,0xfb,0x5d,0x75,0x0b,0xef,0x0f,0x6e,0x6e,0x83,0x59,0x8c,0x30,0xb5,0xe1,0x44,0xd4,0xe4,0x35,0x18,0x96,0x7d,0x5b,0x65,0xb1,0xa5,0x55,0xa8,0x83,0xf8,0x30,0x65,0x4a,0xa2,0xaa,0xc8,0xd3,0xef,0xe9,0x47,0x25,0x4b,0x54,0x5b,0x8a,0x3e,0x7c,0x11,0x84,0xc7,0x96,0x70,0xc2,0x01,0xb1,0xe3,0x18,0xdc,0xa1,0x4d,0x90,0x13,0xab,0x7d,0x7c,0x89,0x50,0xfc,0x6a,0x69,0x04,0x0b,0x6c,0xbd,0x88,0x07,0x88,0x1b,0xcc,0x01,0x17,0x35,0xae,0xc4,0x0a,0xad,0xb9,0x2e,0x08,0x2e,0xcf,0x3c,0x7a,0xb9,0xe3,0x85,0x3e,0x10,0x14,0x96,0x54,0xcc,0x98,0x01,0x4a,0xcc,0x78,0x03,0xbf,0x8f,0xcd,0xed,0xfc,0xcc,0xd3,0x93,0x17,0x62,0x73,0x8c,0xb1,0xa1,0x06,0xd5,0xae,0x07,0x35,0x18,0x96,0x7d,0xca,0x95,0xe2,0x5e,0x8f,0x64,0xdf,0x5f,0x54,0xbd,0x6a,0xcb,0x9d,0x8b,0x89,0xd2,0xb8,0x9c,0xa9,0x0d,0xcc,0x01,0x17,0x35,0x54,0x83,0xb8,0xe7,0x38,0x9e,0x71,0x3a,0x8a,0xfe,0xde,0x8e,0x88,0x6b,0xeb,0x6e,0xc7,0xf9,0xbf,0xea,0x15,0x48,0x93,0xb6,0xf9,0xd0,0xe3,0xd3,0x37,0x8b,0x71,0x70,0x88,0x6b,0xeb,0x6e,0xde,0xdf,0xcc,0xcd,0xac,0xbc,0x83,0xeb,0x77,0xde,0x15,0x41,0x88,0x07,0x88,0x1b,0x9c,0x5b,0x6b,0x35,0x01,0xb0,0xcc,0x46,0xe3,0x5a,0xfa,0xb4,0xf8,0xf5,0x07,0x7c,0xdf,0x4b,0x4e,0x99,0xfe,0xe8,0x33,0x57,0x66,0xa4,0x53,0x1f,0xbf,0x8f,0x50,0x77,0x12,0xbd,0x1b,0x70,0x8f,0x64,0xdf,0x5f,0x5b,0x65,0xb1,0xa5
};

int getkey(int algtype, BYTE* key)
{
	if (algtype == P_AlG_SM1 || algtype == P_AlG_SM4 || algtype == P_AlG_DES3_2Key || algtype == P_AlG_AES128)
	{
		memcpy(key, data, 16);
	}
	else if (algtype == P_AlG_DES)
	{
		memcpy(key, data, 8);
	}
	else if (algtype == P_AlG_DES3_3Key || algtype == P_AlG_AES192)
	{
		memcpy(key, data, 24);
	}
	else if (algtype == P_AlG_AES256)
	{
		memcpy(key, data, 32);
	}
	else
	{
		return -1;
	}

	return 0;
}

void GetAlgAndModeName(int algtype, int algmode, int algop, char** algName, char** modeName)
{
	if (algmode == P_AlG_ECB)
	{
		if (algtype == P_AlG_SM1)
		{
			algop == 0 ? (*algName = "SM1",*modeName = "encrypt ECB") : (*algName = "SM1",*modeName = "decrypt ECB");
		}
		else if (algtype == P_AlG_SM4)
		{
			algop == 0 ? (*algName = "SM4",*modeName = "encrypt ECB") : (*algName = "SM4",*modeName = "decrypt ECB");
		}
		else if (algtype == P_AlG_DES)
		{
			algop == 0 ? (*algName = "DES",*modeName = "encrypt ECB") : (*algName = "DES",*modeName = "decrypt ECB");
		}
		else if (algtype == P_AlG_DES3_2Key)
		{
			algop == 0 ? (*algName = "DES3 2Key",*modeName = "encrypt ECB") : (*algName = "DES3 2Key",*modeName = "decrypt ECB");
		}
		else if (algtype == P_AlG_DES3_3Key)
		{
			algop == 0 ? (*algName = "DES3 3Key",*modeName = "encrypt ECB") : (*algName = "DES3 3Key",*modeName = "decrypt ECB");
		}
		else if (algtype == P_AlG_AES128)
		{
			algop == 0 ? (*algName = "AES128",*modeName = "encrypt ECB") : (*algName = "AES128",*modeName = "decrypt ECB");
		}
		else if (algtype == P_AlG_AES192)
		{
			algop == 0 ? (*algName = "AES192",*modeName = "encrypt ECB") : (*algName = "AES192",*modeName = "decrypt ECB");
		}
		else if (algtype == P_AlG_AES256)
		{
			algop == 0 ? (*algName = "AES256",*modeName = "encrypt ECB") : (*algName = "AES256",*modeName = "decrypt ECB");
		}
	}
	else if (algmode == P_AlG_CBC)
	{
		if (algtype == P_AlG_SM1)
		{
			algop == 0 ? (*algName = "SM1",*modeName = "encrypt CBC") : (*algName = "SM1",*modeName = "decrypt CBC");
		}
		else if (algtype == P_AlG_SM4)
		{
			algop == 0 ? (*algName = "SM4",*modeName = "encrypt CBC") : (*algName = "SM4",*modeName = "decrypt CBC");
		}
		else if (algtype == P_AlG_DES)
		{
			algop == 0 ? (*algName = "DES",*modeName = "encrypt CBC") : (*algName = "DES",*modeName = "decrypt CBC");
		}
		else if (algtype == P_AlG_DES3_2Key)
		{
			algop == 0 ? (*algName = "DES3 2Key",*modeName = "encrypt CBC") : (*algName = "DES3 2Key",*modeName = "decrypt CBC");
		}
		else if (algtype == P_AlG_DES3_3Key)
		{
			algop == 0 ? (*algName = "DES3 3Key",*modeName = "encrypt CBC") : (*algName = "DES3 3Key",*modeName = "decrypt CBC");
		}
		else if (algtype == P_AlG_AES128)
		{
			algop == 0 ? (*algName = "AES128",*modeName = "encrypt CBC") : (*algName = "AES128",*modeName = "decrypt CBC");
		}
		else if (algtype == P_AlG_AES192)
		{
			algop == 0 ? (*algName = "AES192",*modeName = "encrypt CBC") : (*algName = "AES192",*modeName = "decrypt CBC");
		}
		else if (algtype == P_AlG_AES256)
		{
			algop == 0 ? (*algName = "AES256",*modeName = "encrypt CBC") : (*algName = "AES256",*modeName = "decrypt CBC");
		}
	}
	else if (algmode == P_AlG_CFB)
	{
		if (algtype == P_AlG_SM1)
		{
			algop == 0 ? (*algName = "SM1",*modeName = "encrypt CFB") : (*algName = "SM1",*modeName = "decrypt CFB");
		}
		else if (algtype == P_AlG_SM4)
		{
			algop == 0 ? (*algName = "SM4",*modeName = "encrypt CFB") : (*algName = "SM4",*modeName = "decrypt CFB");
		}
		else if (algtype == P_AlG_DES)
		{
			algop == 0 ? (*algName = "DES",*modeName = "encrypt CFB") : (*algName = "DES",*modeName = "decrypt CFB");
		}
		else if (algtype == P_AlG_DES3_2Key)
		{
			algop == 0 ? (*algName = "DES3 2Key",*modeName = "encrypt CFB") : (*algName = "DES3 2Key",*modeName = "decrypt CFB");
		}
		else if (algtype == P_AlG_DES3_3Key)
		{
			algop == 0 ? (*algName = "DES3 3Key",*modeName = "encrypt CFB") : (*algName = "DES3 3Key",*modeName = "decrypt CFB");
		}
		else if (algtype == P_AlG_AES128)
		{
			algop == 0 ? (*algName = "AES128",*modeName = "encrypt CFB") : (*algName = "AES128",*modeName = "decrypt CFB");
		}
		else if (algtype == P_AlG_AES192)
		{
			algop == 0 ? (*algName = "AES192",*modeName = "encrypt CFB") : (*algName = "AES192",*modeName = "decrypt CFB");
		}
		else if (algtype == P_AlG_AES256)
		{
			algop == 0 ? (*algName = "AES256",*modeName = "encrypt CFB") : (*algName = "AES256",*modeName = "decrypt CFB");
		}
	}
	else if (algmode == P_AlG_OFB)
	{
		if (algtype == P_AlG_SM1)
		{
			algop == 0 ? (*algName = "SM1",*modeName = "encrypt OFB") : (*algName = "SM1",*modeName = "decrypt OFB");
		}
		else if (algtype == P_AlG_SM4)
		{
			algop == 0 ? (*algName = "SM4",*modeName = "encrypt OFB") : (*algName = "SM4",*modeName = "decrypt OFB");
		}
		else if (algtype == P_AlG_DES)
		{
			algop == 0 ? (*algName = "DES",*modeName = "encrypt OFB") : (*algName = "DES",*modeName = "decrypt OFB");
		}
		else if (algtype == P_AlG_DES3_2Key)
		{
			algop == 0 ? (*algName = "DES3 2Key",*modeName = "encrypt OFB") : (*algName = "DES3 2Key",*modeName = "decrypt OFB");
		}
		else if (algtype == P_AlG_DES3_3Key)
		{
			algop == 0 ? (*algName = "DES3 3Key",*modeName = "encrypt OFB") : (*algName = "DES3 3Key",*modeName = "decrypt OFB");
		}
		else if (algtype == P_AlG_AES128)
		{
			algop == 0 ? (*algName = "AES128",*modeName = "encrypt OFB") : (*algName = "AES128",*modeName = "decrypt OFB");
		}
		else if (algtype == P_AlG_AES192)
		{
			algop == 0 ? (*algName = "AES192",*modeName = "encrypt OFB") : (*algName = "AES192",*modeName = "decrypt OFB");
		}
		else if (algtype == P_AlG_AES256)
		{
			algop == 0 ? (*algName = "AES256",*modeName = "encrypt OFB") : (*algName = "AES256",*modeName = "decrypt OFB");
		}
	}
}

//
void sym_performances_test(int algtype, int algmode, int algop, unsigned int ulIndataLen)
{
	HANDLE hKey = NULL;
	BYTE bKeyValue[64] = {0};
	BYTE bIVValue[16] = {0};
	UINT ulAlgID = 0;
	BLOCKCIPHERPARAM EncryptParam;
	BYTE* bIndata = NULL, *bOutData = NULL;
	UINT iQuotient = 0, iRemainder = 0;
	UINT i = 0;
	ULONG ulOutdataLen = ulIndataLen;
	char* algName = NULL, *modeName = NULL;
	UINT rv = 0;

	bIndata = (BYTE*)malloc(ulIndataLen + 1);
	if (bIndata == NULL)
	{
		PrintMsg("malloc wrong !");
		return ;
	}
	memset(bIndata, 0x00, ulIndataLen + 1);
	bOutData = (BYTE*)malloc(ulIndataLen + 1);
	if (bOutData == NULL)
	{
		PrintMsg("malloc wrong !");
		return ;
	}
	memset(bOutData, 0x00, ulIndataLen + 1);


	if (algtype == P_AlG_SM1)
	{
		if (algmode == P_AlG_ECB)
		{
			ulAlgID = SGD_SM1_ECB;
		}
		else if (algmode == P_AlG_CBC)
		{
			ulAlgID = SGD_SM1_CBC;
		}
		else if (algmode == P_AlG_CFB)
		{
			ulAlgID = SGD_SM1_CFB;
		}
		else if (algmode == P_AlG_OFB)
		{
			ulAlgID = SGD_SM1_OFB;
		}
	}
	else if (algtype == P_AlG_SM4)
	{
		if (algmode == P_AlG_ECB)
		{
			ulAlgID = SGD_SMS4_ECB;
		}
	}
	else if (algtype == P_AlG_DES)
	{
		if (algmode == P_AlG_ECB)
		{
			//ulAlgID = SGD_DES_ECB;
		}
		else if (algmode == P_AlG_CBC)
		{
			//ulAlgID = SGD_DES_CBC;
		}
	}
	else if (algtype == P_AlG_DES3_2Key)
	{
		if (algmode == P_AlG_ECB)
		{
			//ulAlgID = SGD_DES_ECB;
		}
		else if (algmode == P_AlG_CBC)
		{
			//ulAlgID = SGD_DES_CBC;
		}
	}

	
	getkey(algtype, bKeyValue);
	rv = SKF_SetSymmKey(hDev, bKeyValue, ulAlgID, &hKey);
	EncryptParam.PaddingType = 0;	
	if (algmode == 0)
	{
		EncryptParam.IVLen = 0;
		memset(EncryptParam.IV, 0, 32);
	}
	else
	{
		if (algtype == P_AlG_SM1 || algtype == P_AlG_SM4)
		{
			EncryptParam.IVLen = 16;
			memcpy(EncryptParam.IV, data, 16);
		}
		else
		{
			EncryptParam.IVLen = 8;
			memcpy(EncryptParam.IV, data, 8);
		}
	}

	iQuotient = ulIndataLen / sizeof(data);
	iRemainder = ulIndataLen % sizeof(data);
	for (i = 0; i < iQuotient; i++)
	{
		memcpy(bIndata + i * sizeof(data), data, sizeof(data));
	}
	if (iRemainder > 0)
	{
		memcpy(bIndata + i * sizeof(data), data, iRemainder);
	}
	if (algop == 0)	// 加密
	{
		rv = SKF_EncryptInit(hKey, EncryptParam);
		//SKF_Encrypt(hKey, bIndata, ulIndataLen, NULL, &ulOutdataLen);
		GetBeginTime(&begintime);
		rv = SKF_Encrypt(hKey, bIndata, ulIndataLen, bOutData, &ulOutdataLen);
		GetEndTime(&endtime);
		GetAlgAndModeName(algtype, algmode, algop, &algName, &modeName);
		if (rv == SAR_OK)
		{
			CallSpeed(begintime, endtime, ulIndataLen, algName, modeName);
		}
	}
	else 
	{
		// 解密
		SKF_DecryptInit(hKey, EncryptParam);
		GetBeginTime(&begintime);
		rv = SKF_Decrypt(hKey, bIndata, ulIndataLen, bOutData, &ulOutdataLen);
		GetEndTime(&endtime);
		GetAlgAndModeName(algtype, algmode, algop, &algName, &modeName);
		if (rv == SAR_OK)
		{
			CallSpeed(begintime, endtime, ulIndataLen, algName, modeName);
		}
	}
	SKF_CloseHandle(hKey);

	if (bIndata != NULL)
	{
		free(bIndata);
		bIndata = NULL;
	}
	if (bOutData != NULL)
	{
		free(bOutData);
		bOutData = NULL;
	}
}

void ecc_performances_test()
{
	HCONTAINER hEccContainer = NULL;
	ECCPUBLICKEYBLOB tEccPubBlob;
	ECCSIGNATUREBLOB tEccSignBlob;
	UINT rv = 0;
	ULONG ulSignDataLen = 32;
	BYTE bSignData[] = {		
		0xB1,0xE7,0xFD,0xCB,0x32,0x12,0x1C,0x67,0x3A,0xB7,0x99,0xE5,0xED,0x7B,0xD7,0x86,
		0x60,0xA3,0xA1,0x54,0x30,0x55,0xDB,0x4A,0x0D,0x94,0xD0,0xEF,0xB6,0x98,0x56,0x73
	};
	BYTE bySymkey[16] = {0x37,0xB7,0xE3,0x25,0x9C,0x36,0xE3,0x8E,0xC3,0xA5,0x85,0x86,0x10,0xb5,0xb0,0x7a};
	BYTE bEccPrikey[] = {		
		0xB1,0xE7,0xFD,0xCB,0x32,0x12,0x1C,0x67,0x3A,0xB7,0x99,0xE5,0xED,0x7B,0xD7,0x86,
		0x60,0xA3,0xA1,0x54,0x30,0x55,0xDB,0x4A,0x0D,0x94,0xD0,0xEF,0xB6,0x98,0x56,0x73
	};
	ECCCIPHERBLOB* pEccCipherBlob = NULL;
	ECCPRIVATEKEYBLOB tExtEccPrikeyBlob;
	BYTE bEccDecData[256] = {0};
	ULONG ulEccDecDataLen = 256;
	ECCPUBLICKEYBLOB tExtEccPubkeyBlob;
	BYTE bEccPubkey[] = {	
		0xF0,0x80,0x36,0x1D,0x43,0xE6,0x5B,0x47,0xE8,0xF0,0xD2,0xC1,0x5E,0x99,0x98,0x5E,
		0xD7,0x86,0xED,0x29,0x30,0x8D,0xFF,0xAB,0xB5,0xF0,0x43,0x21,0x6A,0xD6,0x87,0xC2,
		0x50,0x73,0x3E,0x09,0xE0,0x1A,0x48,0xF3,0xBA,0xA5,0xCD,0x7E,0x90,0x35,0xFD,0x76,
		0x6C,0xEB,0x7B,0xFD,0x4D,0x23,0x48,0xA2,0x66,0x94,0x2D,0xBC,0x10,0xE4,0x84,0x56
	};

	rv = SKF_CreateContainer(hApplication, "ECCContainer", &hEccContainer);
	// SKF_GenECCKeyPair
	GetBeginTime(&begintime);
	rv = SKF_GenECCKeyPair(hEccContainer, SGD_SM2_1, &tEccPubBlob);
	GetEndTime(&endtime);
	if (rv == SAR_OK)
	{
		CallSpeed(begintime, endtime, 0, "ECC", "GenKeyPair");
	}

	// SKF_ECCSignData
	GetBeginTime(&begintime);
	rv = SKF_ECCSignData(hEccContainer, bSignData, ulSignDataLen, &tEccSignBlob);
	GetEndTime(&endtime);
	if (rv == SAR_OK)
	{
		CallSpeed(begintime, endtime, 0, "ECC", "SignData");
	}

	// SKF_ECCVerify
	GetBeginTime(&begintime);
	rv = SKF_ECCVerify(hDev, &tEccPubBlob, bSignData, ulSignDataLen, &tEccSignBlob);
	GetEndTime(&endtime);
	if (rv == SAR_OK)
	{
		CallSpeed(begintime, endtime, 0, "ECC", "Verify");
	}

	// SKF_ExtECCEncrypt
	pEccCipherBlob = (ECCCIPHERBLOB*)malloc(sizeof(ECCCIPHERBLOB)*2);
	if (pEccCipherBlob == NULL)
	{
		PrintMsg("malloc wrong !");
		return ;
	}
	memset(pEccCipherBlob, 0x00, sizeof(ECCCIPHERBLOB)*2);
	tExtEccPubkeyBlob.BitLen = 256;
	memcpy(tExtEccPubkeyBlob.XCoordinate + 32, bEccPubkey, 32);
	memcpy(tExtEccPubkeyBlob.YCoordinate + 32, bEccPubkey + 32, 32);
	GetBeginTime(&begintime);
	rv = SKF_ExtECCEncrypt(hDev, &tExtEccPubkeyBlob, bySymkey, 16, pEccCipherBlob);
	GetEndTime(&endtime);
	if (rv == SAR_OK)
	{
		CallSpeed(begintime, endtime, 0, "ECC", "ExtEncrypt");
	}
	
	// SKF_ExtECCDecrypt
	tExtEccPrikeyBlob.BitLen = 256;
	memcpy(tExtEccPrikeyBlob.PrivateKey + 32, bEccPrikey, sizeof(bEccPrikey));
	GetBeginTime(&begintime);
	rv = SKF_ExtECCDecrypt(hDev, &tExtEccPrikeyBlob, pEccCipherBlob, bEccDecData, &ulEccDecDataLen);
	GetEndTime(&endtime);
	if (rv == SAR_OK)
	{
		CallSpeed(begintime, endtime, 0, "ECC", "ExtDecrypt");
	}

#if 0
	//dwq 20181020 start
	// SKF_ECCSignData
	GetBeginTime(&begintime);
	rv = SKF_ExtECCSignSuper(hDev, &tExtEccPrikeyBlob, bSignData, ulSignDataLen, &tEccSignBlob);
	GetEndTime(&endtime);
	if (rv == SAR_OK)
	{
		CallSpeed(begintime, endtime, 0, "ECC", "ExtECCSignSuper");
	}

	// SKF_ECCVerify
	GetBeginTime(&begintime);
	rv = SKF_ExtECCVerifySuper(hDev, &tExtEccPubkeyBlob, bSignData, ulSignDataLen, &tEccSignBlob);
	GetEndTime(&endtime);
	if (rv == SAR_OK)
	{
		CallSpeed(begintime, endtime, 0, "ECC", "ExtECCVerifySuper");
	}

	// SKF_ExtECCEncrypt
	pEccCipherBlob = (ECCCIPHERBLOB*)malloc(sizeof(ECCCIPHERBLOB)*2);
	if (pEccCipherBlob == NULL)
	{
		PrintMsg("malloc wrong !");
		return ;
	}
	memset(pEccCipherBlob, 0x00, sizeof(ECCCIPHERBLOB)*2);
	tExtEccPubkeyBlob.BitLen = 256;
	memcpy(tExtEccPubkeyBlob.XCoordinate + 32, bEccPubkey, 32);
	memcpy(tExtEccPubkeyBlob.YCoordinate + 32, bEccPubkey + 32, 32);
	GetBeginTime(&begintime);
	rv = SKF_ExtECCEncryptSuper(hDev, &tExtEccPubkeyBlob, bySymkey, 16, pEccCipherBlob);
	GetEndTime(&endtime);
	if (rv == SAR_OK)
	{
		CallSpeed(begintime, endtime, 0, "ECC", "ExtECCEncryptSuper");
	}
	
	// SKF_ExtECCDecrypt
	tExtEccPrikeyBlob.BitLen = 256;
	memcpy(tExtEccPrikeyBlob.PrivateKey + 32, bEccPrikey, sizeof(bEccPrikey));
	GetBeginTime(&begintime);
	rv = SKF_ExtECCDecryptSuper(hDev, &tExtEccPrikeyBlob, pEccCipherBlob, bEccDecData, &ulEccDecDataLen);
	GetEndTime(&endtime);
	if (rv == SAR_OK)
	{
		CallSpeed(begintime, endtime, 0, "ECC", "ExtECCDecryptSuper");
	}
	//dwq 20181020 end
#endif

	if (pEccCipherBlob != NULL)
	{
		free(pEccCipherBlob);
		pEccCipherBlob = NULL;
	}
	rv = SKF_CloseContainer(hEccContainer);
	rv = SKF_DeleteContainer(hApplication, "ECCContainer");
}

void rsa_performances_test()
{
	UINT rv = 0;
	HCONTAINER hRSAContainer = NULL;
	RSAPUBLICKEYBLOB tRSAPubBlob;
	BYTE bySignData[117] = {0}, bySignature[128] = {0};
	ULONG ulSignatureLen = 128;
	BYTE byInData[128] = {0}, byOutData[128] = {0};
	ULONG byInDataLen = 128, byOutDataLen = 128;
	RSAPRIVATEKEYBLOB tExtRSAPriBlob;
	BYTE byP[] = {
		0xDA,0x73,0x7D,0xCB,0x35,0x3E,0x2F,0x19,0x38,0x91,0x41,0x70,0xC0,0xF0,0x35,0x42,
		0x08,0x71,0x54,0x1C,0x3F,0x0B,0x1D,0xB6,0xF6,0x2F,0xF6,0x29,0x26,0x2C,0xC2,0xEA,
		0xE0,0xF7,0x7C,0xAF,0x87,0x68,0xD6,0xC2,0x90,0x30,0xD5,0x1B,0x1D,0x3B,0xE7,0x41,
		0x70,0x5A,0xFE,0x88,0x49,0x00,0xD6,0x00,0x45,0x8D,0x5E,0xB4,0xC5,0x5D,0x96,0xD7
	};
	BYTE byQ[] = {
		0xD8,0xDE,0x42,0xE8,0x0B,0x5D,0x9B,0x57,0x1E,0xCC,0x44,0xAF,0xAE,0xBC,0xDC,0x78,
		0xB7,0xFC,0xE4,0x76,0x79,0xBE,0x87,0xDD,0xF2,0x50,0xB8,0x92,0x8A,0x36,0x04,0x23,
		0x59,0xB2,0x4F,0x74,0x54,0xC0,0x5C,0xAD,0xB4,0xE7,0xAE,0xF4,0xBD,0xEC,0xD1,0x8A,
		0x9A,0x69,0x31,0xE1,0xDC,0x55,0xF1,0x7D,0x52,0x0F,0xC1,0x00,0x69,0xCA,0xD3,0x55
	};
	BYTE byDP[] = {
		0x03,0xFF,0x1E,0xEB,0x0B,0xD3,0x52,0x6B,0x44,0xB4,0xAB,0x9C,0xD3,0x7A,0xD1,0x8E,
		0x9E,0xB6,0xEC,0x12,0x04,0x39,0x40,0xD6,0xEB,0x14,0x1F,0x8D,0xCB,0x2C,0x00,0x78,
		0xE9,0x9A,0xBD,0x86,0x3C,0x94,0xF7,0x70,0xE1,0xD0,0x72,0xE5,0xA7,0x18,0x44,0x77,
		0xD7,0x05,0x63,0x28,0xBD,0x25,0x2D,0xC5,0x1D,0x80,0xA3,0x9D,0xED,0x0A,0x74,0x4B
	};
	BYTE byDQ[] = {
		0x1A,0x3D,0xBA,0xA6,0xCD,0x49,0x44,0x54,0xA4,0x5B,0x5F,0x2C,0x4A,0xDE,0x7B,0x66,
		0xF8,0x0C,0x57,0xB0,0xA6,0x46,0x91,0xB6,0x1F,0x6D,0xF9,0x07,0x72,0x45,0xDA,0xF6,
		0x54,0x12,0x29,0x5F,0x10,0x2A,0x3E,0x8C,0x9E,0x49,0x32,0x78,0x56,0xCA,0xE3,0x07,
		0xFC,0x6B,0x22,0x28,0x0C,0x3B,0x31,0xFF,0x52,0x00,0xA9,0xFF,0xDC,0xCD,0x38,0x09
	};
	BYTE byINV[] = {
		0x38,0x12,0x0A,0xC9,0xF4,0x0F,0x9F,0x5E,0xC0,0xB5,0xE6,0x3D,0xC7,0xCB,0x4B,0x90,
		0xB7,0xED,0x76,0x22,0x34,0xE7,0xEF,0x2E,0xAD,0x2B,0xB7,0xC1,0xD3,0x31,0x60,0xC5,
		0x4D,0x51,0xD0,0x08,0x10,0x4F,0xA2,0x19,0x99,0xAE,0x00,0x2E,0x84,0x1E,0x31,0xE6,
		0x8C,0x71,0xD2,0x70,0xBD,0x2E,0xD7,0xAA,0xEB,0x77,0x5B,0x84,0x54,0xED,0x2D,0x16
	};
	BYTE byE[] = {0x00,0x01,0x00,0x01};
	

	rv = SKF_CreateContainer(hApplication, "RSAContainer", &hRSAContainer);
	// SKF_GenRSAKeyPair  1024
	GetBeginTime(&begintime);
	rv = SKF_GenRSAKeyPair(hRSAContainer, 1024, &tRSAPubBlob);
	GetEndTime(&endtime);
	if (rv == SAR_OK)
	{
		CallSpeed(begintime, endtime, 0, "RSA 1024", "GenKeyPair");
	}

	// SKF_RSASignData
	memset(bySignData, 0x11, 117);
	GetBeginTime(&begintime);
	rv = SKF_RSASignData(hRSAContainer, bySignData, 117, bySignature, &ulSignatureLen);
	GetEndTime(&endtime);
	if (rv == SAR_OK)
	{
		CallSpeed(begintime, endtime, 0, "RSA 1024", "SignData");
	}

	// SKF_RSAVerify
	GetBeginTime(&begintime);
	rv = SKF_RSAVerify(hDev, &tRSAPubBlob, bySignData, 117, bySignature, ulSignatureLen);
	GetEndTime(&endtime);
	if (rv == SAR_OK)
	{
		CallSpeed(begintime, endtime, 0, "RSA 1024", "Verify");
	}

	// SKF_ExtRSAPubKeyOperation
	memset(byInData, 0x05, byInDataLen);
	GetBeginTime(&begintime);
	rv = SKF_ExtRSAPubKeyOperation(hDev, &tRSAPubBlob, byInData, byInDataLen, byOutData, &byOutDataLen);
	GetEndTime(&endtime);
	if (rv == SAR_OK)
	{
		CallSpeed(begintime, endtime, 0, "RSA 1024", "ExtPubKeyOperation");
	}

	// SKF_ExtRSAPriKeyOperation
	tExtRSAPriBlob.AlgID = SGD_RSA;
	tExtRSAPriBlob.BitLen = 1024;
	memcpy(tExtRSAPriBlob.Prime1 + 64, byP, sizeof(byP));
	memcpy(tExtRSAPriBlob.Prime2 + 64, byQ, sizeof(byQ));
	memcpy(tExtRSAPriBlob.Prime1Exponent + 64, byDP, sizeof(byDP));
	memcpy(tExtRSAPriBlob.Prime2Exponent + 64, byDQ, sizeof(byDQ));
	memcpy(tExtRSAPriBlob.PublicExponent + 64, byE, sizeof(byE));
	memcpy(tExtRSAPriBlob.Coefficient + 64, byINV, sizeof(byINV));
	GetBeginTime(&begintime);
	rv = SKF_ExtRSAPriKeyOperation(hDev, &tExtRSAPriBlob, byOutData, byOutDataLen, byInData, &byInDataLen);
	GetEndTime(&endtime);
	if (rv == SAR_OK)
	{
		CallSpeed(begintime, endtime, 0, "RSA 1024", "ExtPriKeyOperation");
	}
	rv = SKF_CloseContainer(hRSAContainer);
	rv = SKF_DeleteContainer(hApplication, "RSAContainer");
}

void alg_performances_test()
{
	int i = 0, iAlgType = 0, iAlgMode = 0;
	unsigned int uPlainLen = 0;		//字节为单位
	// iAlgType 对称算法类型 0:SM1	1:SM4  2:DES  3:DES3 2Key  4:DES 3Key  5:AES128 6:AES192 7:AES256 
	// iAlgMode 对称算法模式 0:ECB  1:CBC  2:CFB  3:OFB

	// 对称算法性能测试
	for (i = 0; i < 6; i++)
	{
		uPlainLen = 2 * 1024;
		if (i == 1)
		{
			uPlainLen = 4 * 1024;
		}
		else if (i == 2)
		{
			uPlainLen = 8 * 1024;
		}
		else if (i == 3)
		{
			uPlainLen = 10 * 1024;
		}
		else if (i == 4)
		{
			uPlainLen = 20 * 1024;
		}
		// 私有指令支持算法测试
#if 1
		// SM1 
		for (iAlgMode = 0; iAlgMode < 4; iAlgMode++)
		{
			sym_performances_test(0, iAlgMode, 0x00, uPlainLen);
			sym_performances_test(0, iAlgMode, 0x01, uPlainLen);
		}
		// SM4 ECB
		sym_performances_test(1, 0, 0x00, uPlainLen);
		sym_performances_test(1, 0, 0x01, uPlainLen);
		/*
		// DES ECB/CBC
		for (iAlgMode = 0; iAlgMode < 2; iAlgMode++)
		{
			sym_performances_test(2, iAlgMode, 0x00, uPlainLen);
			sym_performances_test(2, iAlgMode, 0x01, uPlainLen);
		}
		//3DES 2Key  ECB/CBC
		for (iAlgMode = 0; iAlgMode < 2; iAlgMode++)
		{
			sym_performances_test(3, iAlgMode, 0x00, uPlainLen);
			sym_performances_test(3, iAlgMode, 0x01, uPlainLen);
		}
		*/
#endif

#if 0		
		// APDU指令支持算法测试
		for (iAlgType = 0; iAlgType < 2; iAlgType++)
		{
			for (iAlgMode = 0; iAlgMode < 4; iAlgMode++)
			{
				sym_performances_test(iAlgType, iAlgMode, 0x00, uPlainLen);
				sym_performances_test(iAlgType, iAlgMode, 0x01, uPlainLen);
			}
		}
#endif 
	}
#if 1
	// ECC性能测试
	ecc_performances_test();

	// RSA性能测试
	rsa_performances_test();
#endif 
}