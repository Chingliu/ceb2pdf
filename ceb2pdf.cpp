// ceb2pdf.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "CEBFileEngine.h"
#include <iostream>
#include <string>
#include <vector>
using namespace std;

#include <openssl/evp.h>
#include <openssl/rsa.h>
#pragma comment(lib, "libeay32.lib")


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


unsigned char key1 [0x40] =
{
    0x91, 0x43, 0x7c, 0xd8, 0x3d, 0x07, 0x22, 0xce, 0x41, 0x0b, 0xd9, 0x6c, 0xa8, 0x0c, 0xff, 0x34,
    0x89, 0x5a, 0x31, 0x5e, 0x25, 0x12, 0x8b, 0xc3, 0x25, 0x29, 0xd5, 0xf6, 0x14, 0xe4, 0x50, 0x97,
    0xe1, 0x2e, 0x45, 0x0c, 0x68, 0xda, 0xf1, 0xad, 0x8d, 0x8e, 0x74, 0x0a, 0xb7, 0x08, 0x56, 0x4f,
    0x4f, 0x31, 0x7b, 0x80, 0x12, 0xc4, 0x48, 0x56, 0xde, 0x56, 0x7d, 0x58, 0x52, 0x24, 0x97, 0xdb
};
unsigned char key2 [0x40] =
{
    0xf3, 0x84, 0xff, 0x17, 0xa8, 0x16, 0x5a, 0x0e, 0xce, 0xb0, 0xa5, 0x26, 0xf5, 0x44, 0x12, 0xa9,
    0x9a, 0x88, 0xec, 0x69, 0x68, 0xb5, 0xe1, 0x4f, 0xaf, 0x7a, 0x08, 0xbe, 0xe9, 0x2f, 0xfd, 0xe3,
    0x5b, 0x18, 0xc5, 0x46, 0x97, 0xd8, 0x6e, 0xcc, 0x63, 0x97, 0x00, 0xe6, 0x42, 0xbc, 0x91, 0x75,
    0x7e, 0x52, 0x2d, 0xc5, 0xef, 0x4c, 0x95, 0xcc, 0xd7, 0x46, 0xd2, 0xd2, 0x59, 0xdb, 0x00, 0xc5
};

/////////////////////////////////////////////////////////////////////////////
enum
{
    TYPE_3DES_OFB = 1,
    TYPE_3DES_CFB = 2,
    TYPE_3DES_CTS = 3,
    TYPE_IDEA_OFB = 4,
    TYPE_IDEA_CFB = 5,
    TYPE_IDEA_CTS = 6,
    TYPE_RC5_OFB = 7,
    TYPE_RC5_CFB = 8,
    TYPE_RC5_CTS = 9,
    TYPE_RC4_OFB = 10,
    TYPE_RC4_CFB = 11,
    TYPE_RC4_CTS = 12,
    TYPE_CAST256_OFB = 13,
    TYPE_CAST256_CFB = 14,
    TYPE_CAST256_CTS = 15
};

int des_decrypt(int nEncryptStyle, char* pKey, char * szInput, int nInLen, unsigned char *szOutput)
{
    int iOutLen = 0;
    int iTmpLen = 0;        
    char iv[8] = {0};
    // 初始化iv值,应该为输入密码的前8个字节
    memcpy(iv, pKey, 8);
    // 初始化,用到什么加密方式由EVP_des_ede3_ecb()决定的，
    // 如果改为其他加密方式，只要改这个就可以了。    
    EVP_CIPHER_CTX ctx;        
    EVP_CIPHER_CTX_init(&ctx);  
    switch (nEncryptStyle)
    {
    case TYPE_3DES_OFB:
        EVP_EncryptInit_ex(&ctx, EVP_des_ede3_ofb(),
            NULL,
            (const unsigned char *)pKey,
            (const unsigned char *)iv);        //加密    
        break;
    case TYPE_3DES_CFB:
        EVP_EncryptInit_ex(&ctx, EVP_des_ede3_cfb8(),
            NULL,
            (const unsigned char *)pKey,
            (const unsigned char *)iv);        //加密    
        break;
    case TYPE_3DES_CTS:
        break;
    case TYPE_IDEA_OFB:
        break;    
    case TYPE_IDEA_CFB:
        break;    
    case TYPE_IDEA_CTS:
        break;    
    case TYPE_RC5_OFB:
        break;
    case TYPE_RC5_CFB:
        break;
    case TYPE_RC5_CTS:
        break;
    case TYPE_RC4_OFB:
    case TYPE_RC4_CFB:
    case TYPE_RC4_CTS:
    case TYPE_CAST256_OFB:
    case TYPE_CAST256_CFB:
    case TYPE_CAST256_CTS:
    default:
        return 0;
    }

    if(!EVP_EncryptUpdate(&ctx, (unsigned char*)szOutput, &iOutLen, (const unsigned char *)szInput, nInLen))    
    {        
        EVP_CIPHER_CTX_cleanup(&ctx);        
        return 0;    
    }   //结束加密    
    if(!EVP_EncryptFinal_ex(&ctx, (unsigned char *)(szOutput + iOutLen), &iTmpLen))    
    {        
        EVP_CIPHER_CTX_cleanup(&ctx);        
        return 0;    
    }        
    iOutLen += iTmpLen;      
    EVP_CIPHER_CTX_cleanup(&ctx);
    return iOutLen;
}

int rsa_decrypt(unsigned char * szInput, int nInLen, unsigned char *szOutput)
{
    RSA *rsa = NULL;

    if (!szInput || !szOutput)
    {
        return 0;
    }
    rsa = RSA_new();
    BIGNUM *ret, *a, *b, *c;
    BN_CTX *ctx = NULL;
    if ((ctx = BN_CTX_new()) == NULL)
        return NULL;
    BN_CTX_start(ctx);
    ret  = BN_new();
    a  = BN_new();
    b  = BN_new();
    c  = BN_new();
    a->dmax = 16;
    b->dmax = 16;
    c->dmax = nInLen/4;
    a->top = 16;
    b->top = 16;
    c->top = nInLen/4;

    a->d = (BN_ULONG*)key1;
    b->d = (BN_ULONG*)key2;
    c->d = (BN_ULONG*)szInput;
    size_t nOutLen = 0;
    if (!rsa->meth->bn_mod_exp(ret, c, b, a, ctx,rsa->_method_mod_n))
    {
        goto _Exit;
    }
    nOutLen = ret->d[0];
    memcpy(szOutput, (void*)&(ret->d[1]), nOutLen);
_Exit:
    BN_clear_free(ret);
    a->d = NULL;
    b->d = NULL;
    c->d = NULL;
    BN_clear_free(a);
    BN_clear_free(b);
    BN_clear_free(c);
    BN_CTX_free(ctx);
    RSA_free(rsa);
    return (int)nOutLen;

}

typedef struct __tagRC4KEY
{      
    BYTE state[256];       
    BYTE x;        
    BYTE y;
} RC4KEY;

class CRC4CryptoEngine
{
public:
    CRC4CryptoEngine() {}
    virtual ~CRC4CryptoEngine() {}

protected:
    RC4KEY m_RC4Key;     // RC4的加密/解密密钥

public:
    void RC4Crypto(LPBYTE lpbyCryptoText, DWORD dwTextLen)
    {
        BYTE byT, byX, byY;
        BYTE byXorIndex;

        BYTE *pbyState;

        byX = m_RC4Key.x;
        byY = m_RC4Key.y;

        pbyState = &m_RC4Key.state[0];
        for (DWORD dwCounter = 0; dwCounter < dwTextLen; dwCounter++)
        {
            byX = (BYTE)(((int)byX + 1) % 256);
            byY = (BYTE)(((int)pbyState[byX] + byY) % 256);

            byT = pbyState[byX];
            pbyState[byX] = pbyState[byY];
            pbyState[byY] = pbyState[byT];

            byXorIndex = (BYTE)(((int)pbyState[byX] + pbyState[byY]) % 256);
            lpbyCryptoText[dwCounter] ^= pbyState[byXorIndex];
        }               

        m_RC4Key.x = byX;
        m_RC4Key.y = byY;
    }


    void InitialRC4Crypto(LPBYTE lpbyKey, BYTE byKeyLen)    // 初始化
    {
        // Create Seed
        BYTE pbySeed[256];

        for (BYTE i = 0; i < byKeyLen; i++)
        {
            pbySeed[i]  = lpbyKey[i];
            pbySeed[i] |= 0xAA;
        }

        // Prepare RC4 Key
        BYTE byT;
        BYTE byIndex1 = 0;
        BYTE byIndex2 = 0;
        BYTE byCounter;
        BYTE *pbyState;

        pbyState = &m_RC4Key.state[0];
        byCounter = 0;
        while (TRUE)
        {
            pbyState[byCounter] = byCounter;
            if (byCounter == 255)
                break;
            else
                byCounter++;
        }                

        m_RC4Key.x = 0;
        m_RC4Key.y = 0;

        byCounter = 0;
        while (TRUE)
        {
            byIndex2 = (BYTE)(((int)pbySeed[byIndex1] + pbyState[byCounter] + byIndex2) % 256);

            byT = pbyState[byCounter];
            pbyState[byCounter] = pbyState[byIndex2];
            pbyState[byIndex2] = byT;

            byIndex1 = (BYTE)(((int)byIndex1 + 1) % byKeyLen);

            if (byCounter == 255)
                break;
            else
                byCounter++;
        }
    }

    
};

BOOL SetKeyFromCEBFile(CCEBFileEngine& cfe,
    const CEBINDEXITEM& itemAlgorithmID,
    const CEBINDEXITEM& itemKey,
    int& nKeyLength,
    DWORD& dwAlgorithmID,
    BYTE* pPdfKey)
{
    BOOL bRet = FALSE;
    DWORD dwAlgorithmIDOffset = itemAlgorithmID.dwOffsetPos;
    DWORD dwAlgorithmIDLength = itemAlgorithmID.dwDataBlockLength;

    DWORD dwKeyOffset = itemKey.dwOffsetPos;    
    DWORD dwKeyLength = itemKey.dwDataBlockLength;

    if (dwAlgorithmIDLength != sizeof(DWORD))
        return bRet;

    DWORD dwTemp;
    if(!AfxIsValidAddress(cfe.m_pbFile + dwAlgorithmIDOffset,dwAlgorithmIDLength,FALSE))
        return bRet;
    memcpy(&dwTemp,cfe.m_pbFile + dwAlgorithmIDOffset, dwAlgorithmIDLength);
    dwAlgorithmID = dwTemp;

    // 读对称密钥
    BYTE* pKey = new BYTE[dwKeyLength];
    memcpy(pKey,cfe.m_pbFile + dwKeyOffset,dwKeyLength);
    if ((dwAlgorithmID & 0x80000000) != 0)
    {
        // 密钥进行加密了        
        dwAlgorithmID -= 0x80000000;                    
        int nLen = 0;
        if (nLen = rsa_decrypt(pKey, dwKeyLength, pPdfKey))
        {
            if (nLen < 32)
            {
                nKeyLength = nLen;
                bRet = TRUE;
            }
        }
    }
    else
    {
        if (dwKeyLength <= 32)
        {
            memcpy(pPdfKey, pKey, dwKeyLength);
            bRet = TRUE;
        }
        nKeyLength = dwKeyLength;
    }
    delete[] pKey;
    pKey = NULL;
    return bRet;
}

BOOL ceb2pdf(LPCSTR pszCebFileName, LPCSTR pszPdfFileNme = NULL)
{

    BOOL bRet = FALSE;
    if(!pszCebFileName)
        return bRet;

    CString strBookName;
    DWORD dwNodeCount = 0;
    BOOL bKeyExist = FALSE;
    BOOL bAlgorithmIDExist = FALSE;
    BYTE m_pPDFContentStreamKey[32] = {0};
    int m_nPDFContentStreamKeyLength = 24;
    DWORD m_dwPDFContentStreamAlgorithmID = 0;
    CCEBFileEngine cfe(pszCebFileName);
    if (cfe.GetIndexCount() <= 0)
    {
        cfe.Close();
        return FALSE;
    }


    // 查找PDF内容流stream的加密key和加密算法
    CEBINDEXITEM itemEncryptKey;
    CEBINDEXITEM itemEncryptAlgorithmID;        
    bKeyExist = cfe.FindIndexItem(CEB_INDEXTYPE_CSENCRYPTKEY, NULL, itemEncryptKey);    
    bAlgorithmIDExist = cfe.FindIndexItem(CEB_INDEXTYPE_CSENCRYPTALGORITHMID, NULL, itemEncryptAlgorithmID);

    if (bKeyExist && bAlgorithmIDExist)
    {
        bRet = SetKeyFromCEBFile(cfe,
            itemEncryptAlgorithmID,
            itemEncryptKey,
            m_nPDFContentStreamKeyLength,
            m_dwPDFContentStreamAlgorithmID,
            m_pPDFContentStreamKey);
    }
    if (!bRet){
        cfe.Close();
        return FALSE;
    }
    CEBINDEXITEM itemIndex;
    DWORD dwPDFDataLength(0), dwPDFDataOffset(0);
    DWORD dwRC4KeyLength(0), dwRC4KeyOffset(0);

    BOOL bPDFDataExist = FALSE;
    BOOL bRC4KeyExist = FALSE;
    if (cfe.FindIndexItem(CEB_INDEXTYPE_PDFDATA, NULL, itemIndex))
    {
        dwPDFDataOffset = itemIndex.dwOffsetPos;
        dwPDFDataLength = itemIndex.dwDataBlockLength;
        bPDFDataExist = TRUE;
    }

    if (cfe.FindIndexItem(CEB_INDEXTYPE_RC4KEY, NULL, itemIndex))
    {
        dwRC4KeyOffset = itemIndex.dwOffsetPos;
        dwRC4KeyLength = itemIndex.dwDataBlockLength;
        bRC4KeyExist = TRUE;        
    }
    // CreatePDFFile
    bRet = FALSE;
    if (bPDFDataExist && bRC4KeyExist)
    {

        DWORD dwFileSize = (DWORD)cfe.m_cebFile.GetLength();


        if (dwFileSize < dwRC4KeyOffset + dwRC4KeyLength
            ||dwFileSize < dwPDFDataOffset + dwPDFDataLength)
        {
            cfe.Close();
            return FALSE;
        }

        BYTE* pRC4Key = NULL;
        // 得到RC4密钥
        pRC4Key = cfe.m_pbFile + dwRC4KeyOffset;

        CRC4CryptoEngine objTmpRC4;
        objTmpRC4.InitialRC4Crypto(pRC4Key, (BYTE)dwRC4KeyLength);
        CRC4CryptoEngine objRC4;

        LPBYTE pBuffer = cfe.m_pbFile + dwPDFDataOffset;                

        DWORD dwLen = 0,dwPDFLen = dwPDFDataLength;
        int nCount = 0;
        while (dwPDFLen > 0)
        {
            dwLen = 65536;
            if (dwPDFLen < 65536)
            {
                dwLen = dwPDFLen;
            }
            memcpy(&objRC4, &objTmpRC4, sizeof(CRC4CryptoEngine));
            objRC4.RC4Crypto(pBuffer + nCount*65536, dwLen);
            if (dwPDFDataLength < 65536)
            {
                break;
            }
            dwPDFLen -= dwLen;
            nCount++;
        }


        if (m_dwPDFContentStreamAlgorithmID)
        {

            // 解密stream和endstream之间的内容
            DWORD dwStream = 0;
            DWORD dwEndStream = 0;
            DWORD i = 0;
            BYTE *pDeCode = new BYTE[256];
            while (1)
            {
                for (i = dwStream; i < dwPDFDataLength; i++)
                {
                    if (pBuffer[i] == 's' && !memcmp(&pBuffer[i],"stream",6) &&
                        pBuffer[i-1] != 'd')
                    {
                        break;
                    }
                }
                if (i >= dwPDFDataLength)
                {
                    break;
                }
                if (!i)
                {
                    cfe.Close();
                    return FALSE;
                }
                dwStream = i;

                for (i = dwStream; i < dwPDFDataLength; i++)
                {
                    if (pBuffer[i] == 'e' && !memcmp(&pBuffer[i],"endstream",9) )
                    {
                        break;
                    }
                }
                if (!i)
                {
                    cfe.Close();
                    return FALSE;
                }
                if (i >= dwPDFDataLength)
                {
                    break;
                }
                dwEndStream = i;

                while(1)
                {
                    if(pBuffer[dwStream++ +6] == 0x0a)
                    {
                        break;
                    }

                }
                int nBufLen = dwEndStream-dwStream;
                nBufLen -= 6;
                DWORD m =0;
                while(nBufLen>0)
                {
                    int n=0;
                    if (nBufLen>256)
                    {
                        n = 256;
                    }
                    else
                        n = nBufLen;
                    des_decrypt(m_dwPDFContentStreamAlgorithmID,
                        (char*)(&m_pPDFContentStreamKey[0]),
                        (char*)&(pBuffer[dwStream+6+m*256]),
                        n,
                        pDeCode);
                    memcpy(&(pBuffer[dwStream+6+m*256]),pDeCode,n);
                    nBufLen -= 256;
                    m++;
                }
                dwStream = dwEndStream+9;

            }

            delete[] pDeCode;
            pDeCode = NULL;

            //    去掉PDF中的加密标示
            dwPDFLen = dwPDFDataLength;
            while (dwPDFLen--)
            {
                if (pBuffer[dwPDFLen]=='E'&&pBuffer[dwPDFLen+1]=='n')
                {
                    dwPDFLen --;
                    break;                
                }
            }
            DWORD nEN_Start = dwPDFLen;

            while (pBuffer[dwPDFLen++] != 0x0D)
            {
                ;
            }
            DWORD nEN_End = dwPDFLen;

            // 用0x20填充
            memset(&pBuffer[nEN_Start], 0x20, nEN_End - nEN_Start);
        }

        CString strPDFFileName = pszPdfFileNme;
        CString strCEBFileName = pszCebFileName;
        if (strPDFFileName.IsEmpty())
        {
            strPDFFileName = strCEBFileName.Left(strCEBFileName.GetLength() - 4);
            strPDFFileName += ".pdf";

        }
        // 修改文件打开方式为禁止写!防止有的ceb内部文件名一样,创建同名文件而出现错误!
        DeleteFile(strPDFFileName);
        if (1)
        {
            CFile pdffile;
            if (!pdffile.Open(strPDFFileName,
                CFile::modeReadWrite|CFile::shareDenyWrite|CFile::modeCreate))
            {
                cfe.Close();
                return FALSE;
            }
            pdffile.SeekToBegin();
            pdffile.Write(pBuffer,dwPDFDataLength);
            pdffile.Close();
            cfe.Close();
            return TRUE;
        }
    }
    cfe.Close();
    return bRet;
}


void DoCmd(std::string& strCmd)
{
    if (strCmd == "help")
    {
        cout <<endl<< "用法:"<<endl<<endl<<"convert[c]  cebfile  pdffile" << endl<<endl;
        cout <<"1.输入输出文件名路径不能有空格!" << endl <<endl;
        cout <<"2.输出文件名可以忽略,默认生成同名pdf文件!" << endl <<endl;
        cout <<"3.convert命令可以用c代替!" << endl <<endl;
        return;
    }
    std::vector<std::string> str_list; // 存放分割后的字符串
    size_t comma_n = 0;
    do
    {
        std::string tmp_s = "";
        comma_n = strCmd.find( " " );
        if( -1 == comma_n )
        {
            tmp_s = strCmd.substr( 0, strCmd.length() );
            str_list.push_back( tmp_s );
            break;
        }
        tmp_s = strCmd.substr( 0, comma_n );
        strCmd.erase(0, comma_n+1);
        str_list.push_back( tmp_s );
    }
    while(true);

    size_t i = str_list.size();
    if ((str_list[0] == "convert" || str_list[0] == "c")&& i >= 2)
    {
        BOOL bRet = FALSE;
        if (i == 2)
        {
            bRet = ceb2pdf(str_list[1].data());
        }
        else
        {
            bRet = ceb2pdf(str_list[1].data(), str_list[2].data());
        }


        if (bRet)
        {
            cout<<endl<<"done!"<<endl<<endl;
        }
        else
        {
            cout<<endl<<"error!"<<endl<<endl;
        }
    }
    else
    {
        cout <<endl<< "Please type \"help\" to usag and type \"exit\" to exit." << endl<<endl;

    }
    return ;
}


int _tmain(int argc, _TCHAR* argv[])
{
#if 0
    printf("将要转换的pdf文件是%s\n\n",argv[1]);
    // system("PAUSE");
    //// 成功返回1,失败返回0
    BOOL bRet = ceb2pdf("1.ceb");
    printf("\n转换结果:    %d\n\n",bRet);
    //system("PAUSE");
    return 0;
#else
    string strCmd;
    char buf[1024] = {0};
    while ( strCmd != "quit" && strCmd!= "exit")
    {
        cout << "ceb2pdf>" ;
        gets_s(buf);
        strCmd = buf;
        DoCmd(strCmd);
    }
    return 0;
#endif
}
