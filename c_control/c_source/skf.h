#ifndef __SKF_H__
#define __SKF_H__

#include "CommonType.h"


#define MAX_RSA_MODULUS_LEN				256
#define MAX_RSA_EXPONENT_LEN			4
#define ECC_MAX_XCOORDINATE_BITS_LEN	512
#define ECC_MAX_YCOORDINATE_BITS_LEN	512
#define ECC_MAX_MODULUS_BITS_LEN		512
#define MAX_IV_LEN						32

#ifdef __cplusplus
extern "C" {
#endif

// SKF 标准中的一些复合数据类型定义

// 版本
typedef struct Struct_Version{
	BYTE major;						// 主版本号
	BYTE minor;						// 次版本号
}VERSION;

// 设备信息
#pragma pack(push,1)
typedef struct Struct_DEVINFO{
	VERSION		Version;			// 版本号, 设置为1.0
	CHAR		Manufacturer[64];	// 设备厂商信息, 以'\0'为结束符的ASCII字符串
	CHAR		Issuer[64];			// 发行厂商信息, 以'\0'为结束符的ASCII字符串
	CHAR		Label[32];			// 设备标签, 以'\0'为结束符的ASCII字符串
	CHAR		SerialNumber[32];	// 序列号, 以'\0'为结束符的ASCII字符串
	VERSION		HWVersion;			// 设备硬件版本
	VERSION		FirmwareVersion;	// 设备本身固件版本
	ULONG		AlgSymCap;			// 分组密码算法标识
	ULONG		AlgAsymCap;			// 非对称密码算法标识
	ULONG		AlgHashCap;			// 密码杂凑算法标识
	ULONG		DevAuthAlgId;		// 设备认证的分组密码算法标识
	ULONG		TotalSpace;			// 设备总空间大小
	ULONG		FreeSpace;			// 用户可用空间大小
	ULONG		MaxECCBufferSize;	// 能够处理的ECC加密数据大小 
	ULONG		MaxBufferSize;      // 能够处理的分组运算和杂凑运算的数据大小
	BYTE		Reserved[64];		// 保留扩展
}DEVINFO, *PDEVINFO;
#pragma pack(pop)

// RSA公钥数据结构
typedef struct Struct_RSAPUBLICKEYBLOB{
	ULONG AlgID;						// 算法标识
	ULONG BitLen;						// 算法的实际位长度,必须是8的倍数
	BYTE Modulus[MAX_RSA_MODULUS_LEN];	// 模数N
	BYTE PublicExponent[MAX_RSA_EXPONENT_LEN];	// 公开密钥E, 一般固定为00010001
}RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

// RSA私钥数据结构
typedef struct Struct_RSAPRIVATEKEYBLOB{
	ULONG AlgID;									// 算法标识
	ULONG BitLen;									// 算法的实际位长度,必须是8的倍数
	BYTE Modulus[MAX_RSA_MODULUS_LEN];				// 模数N, 实际长度为BitLen/8
	BYTE PublicExponent[MAX_RSA_EXPONENT_LEN];		// 公开密钥E, 一般固定为00010001
	BYTE PrivateExponent[MAX_RSA_MODULUS_LEN];		// 私钥D, 实际长度为BitLen/8
	BYTE Prime1[MAX_RSA_MODULUS_LEN/2];				// 素数p, 实际长度为BitLen/16 
	BYTE Prime2[MAX_RSA_MODULUS_LEN/2];				// 素数q, 实际长度为BitLen/16 
	BYTE Prime1Exponent[MAX_RSA_MODULUS_LEN/2];		// dp, 实际长度为BitLen/16 
	BYTE Prime2Exponent[MAX_RSA_MODULUS_LEN/2];		// dq, 实际长度为BitLen/16
	BYTE Coefficient[MAX_RSA_MODULUS_LEN/2];		// q模p的乘法逆元, 实际长度为BitLen/16
}RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;

// ECC公钥数据结构
typedef struct Struct_ECCPUBLICKEYBLOB{
	ULONG BitLen;									// 模数的实际位长度, 必须是8的倍数
	BYTE XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; // 曲线上点的X坐标
	BYTE YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8]; // 曲线上点的Y坐标
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

// ECC私钥数据结构
typedef struct Struct_ECCPRIVATEKEYBLOB{
	ULONG BitLen;									// 模数的实际位长度, 必须是8的倍数
	BYTE PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8];	// 私有密钥
}ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;


// ECC密文数据结构
typedef struct Struct_ECCCIPHERBLOB{
	BYTE XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE HASH[32];				// 明文的杂凑值
	ULONG CipherLen;			// 密文数据长度
	BYTE Cipher[1];				// 密文数据
} ECCCIPHERBLOB, *PECCCIPHERBLOB;

// ECC签名数据结构
typedef struct Struct_ECCSIGNATUREBLOB{
	BYTE r[ECC_MAX_XCOORDINATE_BITS_LEN/8];		// 签名结构R部分
	BYTE s[ECC_MAX_XCOORDINATE_BITS_LEN/8];		// 签名结构S部分
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

// 分组密码参数
typedef struct Struct_BLOCKCIPHERPARAM{
	BYTE IV[MAX_IV_LEN];			// 初始向量IV
	ULONG IVLen;					// 初始向量的实际长度
	ULONG PaddingType;				// 填充方式, 0表示不填充, 1表示按照PKCS#5方式进行填充
	ULONG FeedBitLen;				// 反馈值的位长度(按位计算),只针对OFB、CFB
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

// ECC加密密钥对保护结构
typedef struct SKF_ENVELOPEDKEYBLOB{
	ULONG Version;							// 当前版本为 1
	ULONG ulSymmAlgID;						// 对称算法标识，限定ECB模式
	ULONG ulBits;							// 加密密钥对的密钥位长度
	BYTE cbEncryptedPriKey[64];				// 加密密钥对私钥的密文
	ECCPUBLICKEYBLOB PubKey;				// 加密密钥对的公钥
	ECCCIPHERBLOB ECCCipherBlob;			// 用保护公钥加密的对称密钥密文。
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

// 文件属性
typedef struct Struct_FILEATTRIBUTE{
	CHAR FileName[32];						// 文件名
	ULONG FileSize;							// 文件大小
	ULONG ReadRights;						// 读取权限
	ULONG WriteRights;						// 写入权限
} FILEATTRIBUTE, *PFILEATTRIBUTE;


// APP信息组包结构
#pragma pack(push,1)
typedef struct _APPPACKDATA
{
    unsigned short DataPackNum; // 包的数量
    UINT COSDataTotalLengh;            // COS的数据总长度
    BYTE DataPackType;      // 数据包类型
    USHORT DataPackSignal;  // 包号
    UCHAR cszAPPData[513];  // APP数据
    unsigned short CRC;     // CRC值
    UINT APPDataLenPer;    // 每包数据长度
} APPPACKDATA,*PAPPPACKDATA;
#pragma pack(pop)

//产品软硬件信息
typedef struct Struct_PRODUCTINFO{
	CHAR CMSVer[32];
	CHAR APPVer[32];
	CHAR COSVer[32];
	CHAR BuildVer[32];
	CHAR SKFVer[32];//SKF版本号，, 以'\0'为结束符的ASCII字符串
	//CHAR CustomName[64];// 客户名称, 以'\0'为结束符的ASCII字符串
	CHAR DataTime[32];			//日期时间, 以'\0'为结束符的ASCII字符串
}PRODUCTINFO, *PPRODUCTINFO;


// 防控权限类型宏定义
#define SECURE_NEVER_ACCOUNT	0x00000000		//不允许
#define	 SECURE_ADM_ACCOUNT		0x00000001		//管理员权限
#define SECURE_USER_ACCOUNT		0x00000010		//用户权限
#define SECURE_ANYONE_ACCOUNT	0x000000FF		//任何人

// 设备状态
#define DEV_ABSENT_STATE     0x00000000			//设备不存在
#define DEV_PRESENT_STATE	0x00000001			//设备存在
#define DEV_UNKNOW_STATE	0x00000002			//设备状态未知

// PIN用户类型
#define ADMIN_TYPE	0
#define USER_TYPE   1

//算法标志
// SM1
#define SGD_SM1_ECB		0x00000101
#define SGD_SM1_CBC		0x00000102
#define SGD_SM1_CFB		0x00000104
#define SGD_SM1_OFB		0x00000108
#define SGD_SM1_MAC		0x00000110
// SM4
#define SGD_SMS4_ECB	0x00000401
#define SGD_SMS4_CBC	0x00000402			
#define SGD_SMS4_CFB	0x00000404			
#define SGD_SMS4_OFB	0x00000408			
// AES
#define SGD_AES128_ECB		0x00000801
#define SGD_AES128_CBC		0x00000802
#define SGD_AES128_CFB		0x00000804
#define SGD_AES128_OFB		0x00000808

#define SGD_AES192_ECB		0x00000811
#define SGD_AES192_CBC		0x00000812
#define SGD_AES192_CFB		0x00000814
#define SGD_AES192_OFB		0x00000818

#define SGD_AES256_ECB		0x00000821
#define SGD_AES256_CBC		0x00000822
#define SGD_AES256_CFB		0x00000824
#define SGD_AES256_OFB		0x00000828
// DES
#define SGD_DES_ECB		0x00001001
#define SGD_DES_CBC		0x00001002
#define SGD_DES_CFB		0x00001004
#define SGD_DES_OFB		0x00001008
// 3DES_2KEY
#define SGD_D3DES_ECB	0x00001011
#define SGD_D3DES_CBC	0x00001012
#define SGD_D3DES_CFB	0x00001014
#define SGD_D3DES_OFB	0x00001018
// 3DES_3KEY
#define SGD_T3DES_ECB	0x00001021
#define SGD_T3DES_CBC	0x00001022
#define SGD_T3DES_CFB	0x00001024
#define SGD_T3DES_OFB	0x00001028

//非对称
#define SGD_RSA		0x00010000
#define SGD_SM2_1	0x00020100			// 椭圆曲线签名算法
#define SGD_SM2_2	0x00020200			// 椭圆曲线密钥交换协议
#define SGD_SM2_3	0x00020400			// 椭圆曲线加密算法

//杂凑算法标志
#define SGD_SM3		0x00000001
#define SGD_SHA1	0x00000002
#define SGD_SHA256	0x00000004


#define SKF_USE_ENCDEC	0x01  //用于加密解密
#define SKF_USE_SIGVER	0x02  //用于签名验证

#define SYSTEM_RESULT_FILE "./systemresult.txt"
#define MOUNT_DIR "/media/wxtstorage"


/*
*设备管理
*/
ULONG DEVAPI SKF_WaitForDevEvent(LPSTR szDevName, ULONG *pulDevNameLen, ULONG *pulEvent);

ULONG DEVAPI SKF_CancelWaitForDevEvent();

ULONG DEVAPI SKF_EnumDev(BOOL bPresent, LPSTR szNameList, ULONG *pulSize);

ULONG DEVAPI SKF_ConnectDev (LPSTR szName, DEVHANDLE *phDev);

ULONG DEVAPI SKF_DisConnectDev (DEVHANDLE hDev);

ULONG DEVAPI SKF_GetDevState(LPSTR szDevName, ULONG *pulDevState);

ULONG DEVAPI SKF_SetLabel (DEVHANDLE hDev, LPSTR szLabel);
// 功能有所扩展
ULONG DEVAPI SKF_GetDevInfo (DEVHANDLE hDev, DEVINFO *pDevInfo);

ULONG DEVAPI SKF_LockDev (DEVHANDLE hDev, ULONG ulTimeOut);

ULONG DEVAPI SKF_UnlockDev (DEVHANDLE hDev);

ULONG DEVAPI SKF_Transmit(DEVHANDLE hDev, BYTE *pbCommand, ULONG ulCommandLen,BYTE *pbData, ULONG *pulDataLen);


/*
*访问控制
*/
ULONG DEVAPI SKF_ChangeDevAuthKey (DEVHANDLE hDev, BYTE *pbKeyValue, ULONG ulKeyLen);

ULONG DEVAPI SKF_DevAuth (DEVHANDLE hDev, BYTE *pbAuthData, ULONG ulLen);

ULONG DEVAPI SKF_ChangePIN (HAPPLICATION hApplication, ULONG ulPINType, LPSTR szOldPin, LPSTR szNewPin, ULONG *pulRetryCount);

ULONG DEVAPI SKF_GetPINInfo(HAPPLICATION hApplication, ULONG ulPINType, ULONG *pulMaxRetryCount, ULONG *pulRemainRetryCount, BOOL *pbDefaultPin);

ULONG DEVAPI SKF_VerifyPIN (HAPPLICATION hApplication, ULONG ulPINType, LPSTR szPIN, ULONG *pulRetryCount);

ULONG DEVAPI SKF_UnblockPIN (HAPPLICATION hApplication, LPSTR szAdminPIN, LPSTR szNewUserPIN, ULONG *pulRetryCount);

ULONG DEVAPI SKF_ClearSecureState (HAPPLICATION hApplication);

/*
*应用管理
*/
ULONG DEVAPI SKF_CreateApplication(DEVHANDLE hDev, LPSTR szAppName, LPSTR szAdminPin, DWORD dwAdminPinRetryCount,LPSTR szUserPin, DWORD dwUserPinRetryCount,DWORD dwCreateFileRights, HAPPLICATION *phApplication);

ULONG DEVAPI SKF_EnumApplication(DEVHANDLE hDev, LPSTR szAppName,ULONG *pulSize);

ULONG DEVAPI SKF_DeleteApplication(DEVHANDLE hDev, LPSTR szAppName);

ULONG DEVAPI SKF_OpenApplication(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION *phApplication);

ULONG DEVAPI SKF_CloseApplication(HAPPLICATION hApplication);


/*
*文件管理
*/
ULONG DEVAPI SKF_CreateFile (HAPPLICATION hApplication, LPSTR szFileName, ULONG ulFileSize, ULONG ulReadRights, ULONG ulWriteRights);

ULONG DEVAPI SKF_DeleteFile (HAPPLICATION hApplication, LPSTR szFileName);

ULONG DEVAPI SKF_EnumFiles (HAPPLICATION hApplication, LPSTR szFileList, ULONG *pulSize);

ULONG DEVAPI SKF_GetFileInfo (HAPPLICATION hApplication, LPSTR szFileName, FILEATTRIBUTE *pFileInfo);

ULONG DEVAPI SKF_ReadFile (HAPPLICATION hApplication, LPSTR szFileName, ULONG ulOffset, ULONG ulSize, BYTE * pbOutData, ULONG *pulOutLen);

ULONG DEVAPI SKF_WriteFile (HAPPLICATION hApplication, LPSTR szFileName, ULONG ulOffset, BYTE *pbData, ULONG ulSize);

/*
*容器管理
*/
ULONG DEVAPI SKF_CreateContainer (HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer);

ULONG DEVAPI SKF_DeleteContainer(HAPPLICATION hApplication, LPSTR szContainerName);

ULONG DEVAPI SKF_OpenContainer(HAPPLICATION hApplication,LPSTR szContainerName,HCONTAINER *phContainer);

ULONG DEVAPI SKF_CloseContainer(HCONTAINER hContainer);

ULONG DEVAPI SKF_EnumContainer (HAPPLICATION hApplication,LPSTR szContainerName,ULONG *pulSize);

ULONG DEVAPI SKF_GetContainerType(HCONTAINER hContainer, ULONG *pulContainerType);

ULONG DEVAPI SKF_ImportCertificate(HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbCert, ULONG ulCertLen);

ULONG DEVAPI SKF_ExportCertificate(HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbCert, ULONG *pulCertLen);

/*
*密码服务
*/
ULONG DEVAPI SKF_GenRandom (DEVHANDLE hDev, BYTE *pbRandom,ULONG ulRandomLen);

ULONG DEVAPI SKF_GenExtRSAKey (DEVHANDLE hDev, ULONG ulBitsLen, RSAPRIVATEKEYBLOB *pBlob);

ULONG DEVAPI SKF_GenRSAKeyPair (HCONTAINER hContainer, ULONG ulBitsLen, RSAPUBLICKEYBLOB *pBlob);

ULONG DEVAPI SKF_ImportRSAKeyPair (HCONTAINER hContainer, ULONG ulSymAlgId, BYTE *pbWrappedKey, ULONG ulWrappedKeyLen, BYTE *pbEncryptedData, ULONG ulEncryptedDataLen);

ULONG DEVAPI SKF_RSASignData(HCONTAINER hContainer, BYTE *pbData, ULONG ulDataLen, BYTE *pbSignature, ULONG *pulSignLen);

ULONG DEVAPI SKF_RSAVerify (DEVHANDLE hDev , RSAPUBLICKEYBLOB *pRSAPubKeyBlob, BYTE *pbData, ULONG ulDataLen, BYTE *pbSignature, ULONG ulSignLen);

ULONG DEVAPI SKF_RSAExportSessionKey (HCONTAINER hContainer, ULONG ulAlgId, RSAPUBLICKEYBLOB *pPubKey, BYTE *pbData, ULONG *pulDataLen, HANDLE *phSessionKey);

ULONG DEVAPI SKF_ExtRSAPubKeyOperation (DEVHANDLE hDev, RSAPUBLICKEYBLOB* pRSAPubKeyBlob,BYTE* pbInput, ULONG ulInputLen, BYTE* pbOutput, ULONG* pulOutputLen);

ULONG DEVAPI SKF_ExtRSAPriKeyOperation (DEVHANDLE hDev, RSAPRIVATEKEYBLOB* pRSAPriKeyBlob,BYTE* pbInput, ULONG ulInputLen, BYTE* pbOutput, ULONG* pulOutputLen);

ULONG DEVAPI SKF_GenECCKeyPair (HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pBlob);

ULONG DEVAPI SKF_ImportECCKeyPair (HCONTAINER hContainer, PENVELOPEDKEYBLOB pEnvelopedKeyBlob);

ULONG DEVAPI SKF_ECCSignData (HCONTAINER hContainer, BYTE *pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);

ULONG DEVAPI SKF_ECCVerify (DEVHANDLE hDev , ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE *pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);

ULONG DEVAPI SKF_ECCExportSessionKey (HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pPubKey, PECCCIPHERBLOB pData, HANDLE *phSessionKey);

ULONG DEVAPI SKF_ExtECCEncrypt (DEVHANDLE hDev, ECCPUBLICKEYBLOB* pECCPubKeyBlob,BYTE* pbPlainText, ULONG ulPlainTextLen, PECCCIPHERBLOB pCipherText);

ULONG DEVAPI SKF_ExtECCDecrypt (DEVHANDLE hDev, ECCPRIVATEKEYBLOB* pECCPriKeyBlob, PECCCIPHERBLOB pCipherText, BYTE* pbPlainText, ULONG* pulPlainTextLen);

ULONG DEVAPI SKF_ExtECCSign (DEVHANDLE hDev, ECCPRIVATEKEYBLOB* pECCPriKeyBlob, BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);

// 功能有所扩展
ULONG DEVAPI SKF_ExtECCVerify (DEVHANDLE hDev, ECCPUBLICKEYBLOB* pECCPubKeyBlob,BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);

#if 0
//dwq 20181020
ULONG DEVAPI SKF_ExtECCEncryptSuper (DEVHANDLE hDev, ECCPUBLICKEYBLOB* pECCPubKeyBlob,BYTE* pbPlainText, ULONG ulPlainTextLen, PECCCIPHERBLOB pCipherText);

ULONG DEVAPI SKF_ExtECCDecryptSuper (DEVHANDLE hDev, ECCPRIVATEKEYBLOB* pECCPriKeyBlob, PECCCIPHERBLOB pCipherText, BYTE* pbPlainText, ULONG* pulPlainTextLen);

ULONG DEVAPI SKF_ExtECCSignSuper (DEVHANDLE hDev, ECCPRIVATEKEYBLOB* pECCPriKeyBlob, BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);

ULONG DEVAPI SKF_ExtECCVerifySuper (DEVHANDLE hDev, ECCPUBLICKEYBLOB* pECCPubKeyBlob,BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);
//
#endif

ULONG DEVAPI SKF_GenerateAgreementDataWithECC (HCONTAINER hContainer, ULONG ulAlgId,ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,BYTE* pbID, ULONG ulIDLen,HANDLE *phAgreementHandle);

ULONG DEVAPI SKF_GenerateAgreementDataAndKeyWithECC(HANDLE hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pSponsorECCPubKeyBlob, ECCPUBLICKEYBLOB* pSponsorTempECCPubKeyBlob,
	ECCPUBLICKEYBLOB* pTempECCPubKeyBlob, BYTE* pbID, ULONG ulIDLen, BYTE *pbSponsorID, ULONG ulSponsorIDLen, HANDLE *phKeyHandle);

ULONG DEVAPI SKF_GenerateKeyWithECC (HANDLE hAgreementHandle, ECCPUBLICKEYBLOB* pECCPubKeyBlob, ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
									 BYTE* pbID, ULONG ulIDLen, HANDLE *phKeyHandle);

ULONG DEVAPI SKF_ExportPublicKey (HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbBlob, ULONG* pulBlobLen);

ULONG DEVAPI SKF_ImportSessionKey (HCONTAINER hContainer, ULONG ulAlgId, BYTE *pbWrapedData,ULONG ulWrapedLen ,HANDLE *phKey);

ULONG DEVAPI SKF_SetSymmKey (DEVHANDLE hDev, BYTE *pbKey, ULONG ulAlgID, HANDLE *phKey);

ULONG DEVAPI SKF_EncryptInit (HANDLE hKey, BLOCKCIPHERPARAM EncryptParam);

ULONG DEVAPI SKF_Encrypt(HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);

ULONG DEVAPI SKF_EncryptUpdate(HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);

ULONG DEVAPI SKF_EncryptFinal (HANDLE hKey, BYTE *pbEncryptedData, ULONG *pulEncryptedDataLen );

ULONG DEVAPI SKF_DecryptInit (HANDLE hKey, BLOCKCIPHERPARAM DecryptParam);

ULONG DEVAPI SKF_Decrypt(HANDLE hKey, BYTE * pbEncryptedData, ULONG ulEncryptedLen, BYTE * pbData, ULONG * pulDataLen);

ULONG DEVAPI SKF_DecryptUpdate(HANDLE hKey, BYTE * pbEncryptedData, ULONG ulEncryptedLen, BYTE * pbData, ULONG * pulDataLen);

ULONG DEVAPI SKF_DecryptFinal (HANDLE hKey, BYTE *pbDecryptedData, ULONG *pulDecryptedDataLen);

ULONG DEVAPI SKF_DigestInit(DEVHANDLE hDev, ULONG ulAlgID, ECCPUBLICKEYBLOB *pPubKey, unsigned char *pucID, ULONG ulIDLen, HANDLE *phHash);

ULONG DEVAPI SKF_Digest (HANDLE hHash, BYTE *pbData, ULONG ulDataLen, BYTE *pbHashData, ULONG *pulHashLen);

ULONG DEVAPI SKF_DigestUpdate (HANDLE hHash, BYTE *pbData, ULONG ulDataLen);

ULONG DEVAPI SKF_DigestFinal (HANDLE hHash, BYTE *pHashData, ULONG *pulHashLen);

ULONG DEVAPI SKF_MacInit (HANDLE hKey, BLOCKCIPHERPARAM *pMacParam, HANDLE *phMac);

ULONG DEVAPI SKF_Mac(HANDLE hMac, BYTE* pbData, ULONG ulDataLen, BYTE *pbMacData, ULONG *pulMacLen);

ULONG DEVAPI SKF_MacUpdate(HANDLE hMac, BYTE * pbData, ULONG ulDataLen);

ULONG DEVAPI SKF_MacFinal (HANDLE hMac, BYTE *pbMacData, ULONG *pulMacDataLen);

ULONG DEVAPI SKF_CloseHandle(HANDLE hHandle);

// 非标准扩展接口
// 扩展接口
ULONG DEVAPI SKFE_SetSN( DEVHANDLE hDev, CHAR* SN, UINT SNLen);
ULONG DEVAPI SKFE_GenExtECCKey(DEVHANDLE hDev, PECCPRIVATEKEYBLOB pPriBlob, PECCPUBLICKEYBLOB pPubBlob);
// 功能有所扩展
ULONG DEVAPI SKF_ECCDecrypt(HCONTAINER hContainer, PECCCIPHERBLOB pCipherText, BYTE *pbPlainText,ULONG *pulPlainTextLen);
ULONG DEVAPI SKFE_ECCDecryptSignKey(HCONTAINER hContainer, PECCCIPHERBLOB pCipherText, BYTE *pbPlainText,ULONG *pulPlainTextLen);
// 扩展接口
ULONG DEVAPI SKF_ImportPlainECCKeyPair(HCONTAINER hContainer, PECCPRIVATEKEYBLOB pPriBlob, PECCPUBLICKEYBLOB pPubBlob, UINT pKeyType );
ULONG DEVAPI SKFE_GetFirmwareVer(DEVHANDLE hDev,BYTE *pbFirmwareVer,ULONG *ulFirmwareVerLen);

ULONG DEVAPI SKFE_GetProductInfo(HANDLE hDev, PPRODUCTINFO pProductInfo);

// 信工所添加的函数
// ECC数字信封转换并输出数字信封
ULONG DEVAPI SKFE_ECCDigitalEnvelopTransform(DEVHANDLE hDev,HCONTAINER hContainer,PECCCIPHERBLOB pBeforeECCCipherBlob,PECCPUBLICKEYBLOB pPubBlob,PECCCIPHERBLOB pAfterECCCipherBlob);

#ifndef ANDROID
ULONG DEVAPI SKFE_UpdateFirmware(LPSTR szDevPath, BYTE *FirmwareData, ULONG FirmwareSize);
#endif
ULONG DEVAPI SKFE_GetHwCode(DEVHANDLE hDev, BYTE *pHwCode, ULONG *pulHwCodeLen);

ULONG DEVAPI SKFE_GetFwPublicKey(DEVHANDLE hDev, BYTE *pucPublicKey, ULONG *pulLen);

ULONG DEVAPI SKFE_IssueCard();

// 河北CA添加的函数
#if 0
ULONG DEVAPI SKF_GenerateKey(HCONTAINER hContainer, ULONG ulAlgId, HANDLE *phSessionKey) ;
ULONG DEVAPI SKF_ECCExportSessionKeyByHandle (HANDLE phSessionKey, ECCPUBLICKEYBLOB *pPubKey,PECCCIPHERBLOB pData);
ULONG DEVAPI SKF_RSAExportSessionKeyByHandle (HANDLE phSessionKey, RSAPUBLICKEYBLOB*pPubKey,BYTE *pbData, ULONG *pulDataLen);
// ULONG DEVAPI SKF_PrvKeyDecrypt(HCONTAINER hContainer,  PECCCIPHERBLOB pCipherText, BYTE *pbData, ULONG *pbDataLen  );
ULONG DEVAPI SKF_PrvKeyDecrypt(HCONTAINER hContainer, ULONG ulType, PECCCIPHERBLOB pCipherText, BYTE *pbData, ULONG *pbDataLen  );
ULONG DEVAPI SKF_RSAPrvKeyDecrypt(HCONTAINER hContainer, BYTE *pCipherData, ULONG pCipherDataLen, BYTE *pbData, ULONG *pbDataLen );

#endif


#ifdef __cplusplus
 }	
#endif

#endif	//__SKF_H__
