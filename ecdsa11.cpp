#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define  SIGN_PATH			"./.message.sign"  //签名文件
#define  SOURCE_PATH		"./source_file"    //源文件

#define PUBLIC_KEY_PASH	    "./pub_key.pem"  //公钥

static EVP_PKEY* PEM_read_PublicKey(FILE* fp)
{
	BIO* b;
	EVP_PKEY* ret;

	if ((b = BIO_new(BIO_s_file())) == NULL)
	{
		//PEMerr(PEM_F_PEM_READ_PRIVATEKEY, ERR_R_BUF_LIB);
		return(0);
	}
	BIO_set_fp(b, fp, BIO_NOCLOSE);
	ret = PEM_read_bio_PUBKEY(b, NULL, NULL, NULL);
	BIO_free(b);
	return(ret);
}

static EVP_PKEY* Read_PublicKey(char* p_KeyPath)
{
	FILE* fp = NULL;
	char szKeyPath[1024];
	EVP_PKEY* pubRsa = NULL;

	/*	打开密钥文件 */
	fopen_s(&fp, p_KeyPath, "r");
	
	/*	获取私密钥 */
	pubRsa = PEM_read_PublicKey(fp);
	if (NULL == pubRsa)
	{
		fclose(fp);
		return NULL;
	}
	fclose(fp);

	return pubRsa;
}

int VerifyUpgrade(char* sign_data, int sign_len)
{
	printf("sign_len = %d\n", sign_len);

	int nRet = 0;
	EVP_PKEY* pKey;
	EVP_MD_CTX* pMdCtx = NULL;
	EVP_PKEY_CTX* pKeyCtx = NULL;

	/*初始化验签函数*/
	pKey = Read_PublicKey((char*)PUBLIC_KEY_PASH);
	if (!pKey)
	{
		printf("Read_PublicKey failed!\n");
		return -1;
	}

	pMdCtx = EVP_MD_CTX_create();
	if (NULL == pMdCtx)
	{
		printf("EVP_MD_CTX_create failed!\n");
		EVP_PKEY_free(pKey);
		pKey = NULL;
		return -1;
	}

	nRet = EVP_DigestVerifyInit(pMdCtx, &pKeyCtx, EVP_sha256(), NULL, pKey);
	if (nRet <= 0)
	{
		printf("EVP_DigestVerifyInit failed!\n");
		EVP_PKEY_free(pKey);
		pKey = NULL;
		EVP_MD_CTX_destroy(pMdCtx);
		pMdCtx = NULL;
		return -1;
	}

	FILE* fp = NULL;
	char p_pBuf[512];
	fopen_s(&fp,SOURCE_PATH, "r");
	while (feof(fp) == 0)
	{
		int i = fread(p_pBuf, 1, 512, fp);
		EVP_DigestVerifyUpdate(pMdCtx, p_pBuf, i);
	}


	/*验签*/
	nRet = EVP_DigestVerifyFinal(pMdCtx, (unsigned char*)sign_data, sign_len);
	if (nRet <= 0)
	{
		printf("EVP_DigestVerifyFinal failed !!! nRet = %d \n", nRet);
		EVP_PKEY_free(pKey);
		pKey = NULL;
		EVP_MD_CTX_destroy(pMdCtx);
		pMdCtx = NULL;
		fclose(fp);
		printf("========================= Verify Failed ========================\n");
		return -1;
	}
	fclose(fp);

	printf("========================= Verify Success ========================\n");

	return 0;
}

int main()
{
	int sign_len = 0;
	char* p_sign_data = NULL;

	struct stat statbuf;
	stat(SIGN_PATH, &statbuf);
	sign_len = statbuf.st_size;

	p_sign_data = (char*)malloc(sign_len);
	memset(p_sign_data, 0, sign_len);
	FILE* sign_fp;
	fopen_s(&sign_fp,SIGN_PATH, "r");
	if (sign_fp)
	{
		fread(p_sign_data, 1, sign_len, sign_fp);
	}

	VerifyUpgrade(p_sign_data, sign_len);

	free(p_sign_data);

	return 0;
}