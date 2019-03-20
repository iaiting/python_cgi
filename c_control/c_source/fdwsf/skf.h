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

// SKF ��׼�е�һЩ�����������Ͷ���

// �汾
typedef struct Struct_Version{
	BYTE major;						// ���汾��
	BYTE minor;						// �ΰ汾��
}VERSION;

// �豸��Ϣ
#pragma pack(push,1)
typedef struct Struct_DEVINFO{
	VERSION		Version;			// �汾��, ����Ϊ1.0
	CHAR		Manufacturer[64];	// �豸������Ϣ, ��'\0'Ϊ��������ASCII�ַ���
	CHAR		Issuer[64];			// ���г�����Ϣ, ��'\0'Ϊ��������ASCII�ַ���
	CHAR		Label[32];			// �豸��ǩ, ��'\0'Ϊ��������ASCII�ַ���
	CHAR		SerialNumber[32];	// ���к�, ��'\0'Ϊ��������ASCII�ַ���
	VERSION		HWVersion;			// �豸Ӳ���汾
	VERSION		FirmwareVersion;	// �豸����̼��汾
	ULONG		AlgSymCap;			// ���������㷨��ʶ
	ULONG		AlgAsymCap;			// �ǶԳ������㷨��ʶ
	ULONG		AlgHashCap;			// �����Ӵ��㷨��ʶ
	ULONG		DevAuthAlgId;		// �豸��֤�ķ��������㷨��ʶ
	ULONG		TotalSpace;			// �豸�ܿռ��С
	ULONG		FreeSpace;			// �û����ÿռ��С
	ULONG		MaxECCBufferSize;	// �ܹ������ECC�������ݴ�С 
	ULONG		MaxBufferSize;      // �ܹ�����ķ���������Ӵ���������ݴ�С
	BYTE		Reserved[64];		// ������չ
}DEVINFO, *PDEVINFO;
#pragma pack(pop)

// RSA��Կ���ݽṹ
typedef struct Struct_RSAPUBLICKEYBLOB{
	ULONG AlgID;						// �㷨��ʶ
	ULONG BitLen;						// �㷨��ʵ��λ����,������8�ı���
	BYTE Modulus[MAX_RSA_MODULUS_LEN];	// ģ��N
	BYTE PublicExponent[MAX_RSA_EXPONENT_LEN];	// ������ԿE, һ��̶�Ϊ00010001
}RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

// RSA˽Կ���ݽṹ
typedef struct Struct_RSAPRIVATEKEYBLOB{
	ULONG AlgID;									// �㷨��ʶ
	ULONG BitLen;									// �㷨��ʵ��λ����,������8�ı���
	BYTE Modulus[MAX_RSA_MODULUS_LEN];				// ģ��N, ʵ�ʳ���ΪBitLen/8
	BYTE PublicExponent[MAX_RSA_EXPONENT_LEN];		// ������ԿE, һ��̶�Ϊ00010001
	BYTE PrivateExponent[MAX_RSA_MODULUS_LEN];		// ˽ԿD, ʵ�ʳ���ΪBitLen/8
	BYTE Prime1[MAX_RSA_MODULUS_LEN/2];				// ����p, ʵ�ʳ���ΪBitLen/16 
	BYTE Prime2[MAX_RSA_MODULUS_LEN/2];				// ����q, ʵ�ʳ���ΪBitLen/16 
	BYTE Prime1Exponent[MAX_RSA_MODULUS_LEN/2];		// dp, ʵ�ʳ���ΪBitLen/16 
	BYTE Prime2Exponent[MAX_RSA_MODULUS_LEN/2];		// dq, ʵ�ʳ���ΪBitLen/16
	BYTE Coefficient[MAX_RSA_MODULUS_LEN/2];		// qģp�ĳ˷���Ԫ, ʵ�ʳ���ΪBitLen/16
}RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;

// ECC��Կ���ݽṹ
typedef struct Struct_ECCPUBLICKEYBLOB{
	ULONG BitLen;									// ģ����ʵ��λ����, ������8�ı���
	BYTE XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; // �����ϵ��X����
	BYTE YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8]; // �����ϵ��Y����
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

// ECC˽Կ���ݽṹ
typedef struct Struct_ECCPRIVATEKEYBLOB{
	ULONG BitLen;									// ģ����ʵ��λ����, ������8�ı���
	BYTE PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8];	// ˽����Կ
}ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;


// ECC�������ݽṹ
typedef struct Struct_ECCCIPHERBLOB{
	BYTE XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE HASH[32];				// ���ĵ��Ӵ�ֵ
	ULONG CipherLen;			// �������ݳ���
	BYTE Cipher[1];				// ��������
} ECCCIPHERBLOB, *PECCCIPHERBLOB;

// ECCǩ�����ݽṹ
typedef struct Struct_ECCSIGNATUREBLOB{
	BYTE r[ECC_MAX_XCOORDINATE_BITS_LEN/8];		// ǩ���ṹR����
	BYTE s[ECC_MAX_XCOORDINATE_BITS_LEN/8];		// ǩ���ṹS����
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

// �����������
typedef struct Struct_BLOCKCIPHERPARAM{
	BYTE IV[MAX_IV_LEN];			// ��ʼ����IV
	ULONG IVLen;					// ��ʼ������ʵ�ʳ���
	ULONG PaddingType;				// ��䷽ʽ, 0��ʾ�����, 1��ʾ����PKCS#5��ʽ�������
	ULONG FeedBitLen;				// ����ֵ��λ����(��λ����),ֻ���OFB��CFB
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

// ECC������Կ�Ա����ṹ
typedef struct SKF_ENVELOPEDKEYBLOB{
	ULONG Version;							// ��ǰ�汾Ϊ 1
	ULONG ulSymmAlgID;						// �Գ��㷨��ʶ���޶�ECBģʽ
	ULONG ulBits;							// ������Կ�Ե���Կλ����
	BYTE cbEncryptedPriKey[64];				// ������Կ��˽Կ������
	ECCPUBLICKEYBLOB PubKey;				// ������Կ�ԵĹ�Կ
	ECCCIPHERBLOB ECCCipherBlob;			// �ñ�����Կ���ܵĶԳ���Կ���ġ�
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

// �ļ�����
typedef struct Struct_FILEATTRIBUTE{
	CHAR FileName[32];						// �ļ���
	ULONG FileSize;							// �ļ���С
	ULONG ReadRights;						// ��ȡȨ��
	ULONG WriteRights;						// д��Ȩ��
} FILEATTRIBUTE, *PFILEATTRIBUTE;


// APP��Ϣ����ṹ
#pragma pack(push,1)
typedef struct _APPPACKDATA
{
    unsigned short DataPackNum; // ��������
    UINT COSDataTotalLengh;            // COS�������ܳ���
    BYTE DataPackType;      // ���ݰ�����
    USHORT DataPackSignal;  // ����
    UCHAR cszAPPData[513];  // APP����
    unsigned short CRC;     // CRCֵ
    UINT APPDataLenPer;    // ÿ�����ݳ���
} APPPACKDATA,*PAPPPACKDATA;
#pragma pack(pop)

//��Ʒ��Ӳ����Ϣ
typedef struct Struct_PRODUCTINFO{
	CHAR CMSVer[32];
	CHAR APPVer[32];
	CHAR COSVer[32];
	CHAR BuildVer[32];
	CHAR SKFVer[32];//SKF�汾�ţ�, ��'\0'Ϊ��������ASCII�ַ���
	//CHAR CustomName[64];// �ͻ�����, ��'\0'Ϊ��������ASCII�ַ���
	CHAR DataTime[32];			//����ʱ��, ��'\0'Ϊ��������ASCII�ַ���
}PRODUCTINFO, *PPRODUCTINFO;


// ����Ȩ�����ͺ궨��
#define SECURE_NEVER_ACCOUNT	0x00000000		//������
#define	 SECURE_ADM_ACCOUNT		0x00000001		//����ԱȨ��
#define SECURE_USER_ACCOUNT		0x00000010		//�û�Ȩ��
#define SECURE_ANYONE_ACCOUNT	0x000000FF		//�κ���

// �豸״̬
#define DEV_ABSENT_STATE     0x00000000			//�豸������
#define DEV_PRESENT_STATE	0x00000001			//�豸����
#define DEV_UNKNOW_STATE	0x00000002			//�豸״̬δ֪

// PIN�û�����
#define ADMIN_TYPE	0
#define USER_TYPE   1

//�㷨��־
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

//�ǶԳ�
#define SGD_RSA		0x00010000
#define SGD_SM2_1	0x00020100			// ��Բ����ǩ���㷨
#define SGD_SM2_2	0x00020200			// ��Բ������Կ����Э��
#define SGD_SM2_3	0x00020400			// ��Բ���߼����㷨

//�Ӵ��㷨��־
#define SGD_SM3		0x00000001
#define SGD_SHA1	0x00000002
#define SGD_SHA256	0x00000004


#define SKF_USE_ENCDEC	0x01  //���ڼ��ܽ���
#define SKF_USE_SIGVER	0x02  //����ǩ����֤

#define SYSTEM_RESULT_FILE "./systemresult.txt"
#define MOUNT_DIR "/media/wxtstorage"


/*
*�豸����
*/
ULONG DEVAPI SKF_WaitForDevEvent(LPSTR szDevName, ULONG *pulDevNameLen, ULONG *pulEvent);

ULONG DEVAPI SKF_CancelWaitForDevEvent();

ULONG DEVAPI SKF_EnumDev(BOOL bPresent, LPSTR szNameList, ULONG *pulSize);

ULONG DEVAPI SKF_ConnectDev (LPSTR szName, DEVHANDLE *phDev);

ULONG DEVAPI SKF_DisConnectDev (DEVHANDLE hDev);

ULONG DEVAPI SKF_GetDevState(LPSTR szDevName, ULONG *pulDevState);

ULONG DEVAPI SKF_SetLabel (DEVHANDLE hDev, LPSTR szLabel);
// ����������չ
ULONG DEVAPI SKF_GetDevInfo (DEVHANDLE hDev, DEVINFO *pDevInfo);

ULONG DEVAPI SKF_LockDev (DEVHANDLE hDev, ULONG ulTimeOut);

ULONG DEVAPI SKF_UnlockDev (DEVHANDLE hDev);

ULONG DEVAPI SKF_Transmit(DEVHANDLE hDev, BYTE *pbCommand, ULONG ulCommandLen,BYTE *pbData, ULONG *pulDataLen);


/*
*���ʿ���
*/
ULONG DEVAPI SKF_ChangeDevAuthKey (DEVHANDLE hDev, BYTE *pbKeyValue, ULONG ulKeyLen);

ULONG DEVAPI SKF_DevAuth (DEVHANDLE hDev, BYTE *pbAuthData, ULONG ulLen);

ULONG DEVAPI SKF_ChangePIN (HAPPLICATION hApplication, ULONG ulPINType, LPSTR szOldPin, LPSTR szNewPin, ULONG *pulRetryCount);

ULONG DEVAPI SKF_GetPINInfo(HAPPLICATION hApplication, ULONG ulPINType, ULONG *pulMaxRetryCount, ULONG *pulRemainRetryCount, BOOL *pbDefaultPin);

ULONG DEVAPI SKF_VerifyPIN (HAPPLICATION hApplication, ULONG ulPINType, LPSTR szPIN, ULONG *pulRetryCount);

ULONG DEVAPI SKF_UnblockPIN (HAPPLICATION hApplication, LPSTR szAdminPIN, LPSTR szNewUserPIN, ULONG *pulRetryCount);

ULONG DEVAPI SKF_ClearSecureState (HAPPLICATION hApplication);

/*
*Ӧ�ù���
*/
ULONG DEVAPI SKF_CreateApplication(DEVHANDLE hDev, LPSTR szAppName, LPSTR szAdminPin, DWORD dwAdminPinRetryCount,LPSTR szUserPin, DWORD dwUserPinRetryCount,DWORD dwCreateFileRights, HAPPLICATION *phApplication);

ULONG DEVAPI SKF_EnumApplication(DEVHANDLE hDev, LPSTR szAppName,ULONG *pulSize);

ULONG DEVAPI SKF_DeleteApplication(DEVHANDLE hDev, LPSTR szAppName);

ULONG DEVAPI SKF_OpenApplication(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION *phApplication);

ULONG DEVAPI SKF_CloseApplication(HAPPLICATION hApplication);


/*
*�ļ�����
*/
ULONG DEVAPI SKF_CreateFile (HAPPLICATION hApplication, LPSTR szFileName, ULONG ulFileSize, ULONG ulReadRights, ULONG ulWriteRights);

ULONG DEVAPI SKF_DeleteFile (HAPPLICATION hApplication, LPSTR szFileName);

ULONG DEVAPI SKF_EnumFiles (HAPPLICATION hApplication, LPSTR szFileList, ULONG *pulSize);

ULONG DEVAPI SKF_GetFileInfo (HAPPLICATION hApplication, LPSTR szFileName, FILEATTRIBUTE *pFileInfo);

ULONG DEVAPI SKF_ReadFile (HAPPLICATION hApplication, LPSTR szFileName, ULONG ulOffset, ULONG ulSize, BYTE * pbOutData, ULONG *pulOutLen);

ULONG DEVAPI SKF_WriteFile (HAPPLICATION hApplication, LPSTR szFileName, ULONG ulOffset, BYTE *pbData, ULONG ulSize);

/*
*��������
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
*�������
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

// ����������չ
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

// �Ǳ�׼��չ�ӿ�
// ��չ�ӿ�
ULONG DEVAPI SKFE_SetSN( DEVHANDLE hDev, CHAR* SN, UINT SNLen);
ULONG DEVAPI SKFE_GenExtECCKey(DEVHANDLE hDev, PECCPRIVATEKEYBLOB pPriBlob, PECCPUBLICKEYBLOB pPubBlob);
// ����������չ
ULONG DEVAPI SKF_ECCDecrypt(HCONTAINER hContainer, PECCCIPHERBLOB pCipherText, BYTE *pbPlainText,ULONG *pulPlainTextLen);
ULONG DEVAPI SKFE_ECCDecryptSignKey(HCONTAINER hContainer, PECCCIPHERBLOB pCipherText, BYTE *pbPlainText,ULONG *pulPlainTextLen);
// ��չ�ӿ�
ULONG DEVAPI SKF_ImportPlainECCKeyPair(HCONTAINER hContainer, PECCPRIVATEKEYBLOB pPriBlob, PECCPUBLICKEYBLOB pPubBlob, UINT pKeyType );
ULONG DEVAPI SKFE_GetFirmwareVer(DEVHANDLE hDev,BYTE *pbFirmwareVer,ULONG *ulFirmwareVerLen);

ULONG DEVAPI SKFE_GetProductInfo(HANDLE hDev, PPRODUCTINFO pProductInfo);

// �Ź�����ӵĺ���
// ECC�����ŷ�ת������������ŷ�
ULONG DEVAPI SKFE_ECCDigitalEnvelopTransform(DEVHANDLE hDev,HCONTAINER hContainer,PECCCIPHERBLOB pBeforeECCCipherBlob,PECCPUBLICKEYBLOB pPubBlob,PECCCIPHERBLOB pAfterECCCipherBlob);

#ifndef ANDROID
ULONG DEVAPI SKFE_UpdateFirmware(LPSTR szDevPath, BYTE *FirmwareData, ULONG FirmwareSize);
#endif
ULONG DEVAPI SKFE_GetHwCode(DEVHANDLE hDev, BYTE *pHwCode, ULONG *pulHwCodeLen);

ULONG DEVAPI SKFE_GetFwPublicKey(DEVHANDLE hDev, BYTE *pucPublicKey, ULONG *pulLen);

ULONG DEVAPI SKFE_IssueCard();

// �ӱ�CA��ӵĺ���
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
