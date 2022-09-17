#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include <string>
#include <openssl/pem.h>

#include<conio.h>

#include<sstream>

#include <fstream>


#include <windows.h>　

#define random(a,b) (rand()%(b-a)+a)
#define EC_POINT_SIZE 256
extern "C"
{
#include <openssl/applink.c>
}
using namespace std;
string ReadLine(const char* filename, int line)
{
    int i = 0;
    string temp;
    fstream file;
    file.open(filename, ios::in);

    if (line <= 0)
    {
        return "Error 1: 行数错误，不能为0或负数。";
    }

    if (file.fail())
    {
        return "Error 2: 文件不存在。";
    }

    while (getline(file, temp) && i < line - 1)
    {
        i++;
    }

    file.close();
    return temp;
}
void printHex(const unsigned char* pBuf, int nLen)
{
    for (int i = 0; i < nLen; i++)
    {
        printf("%02X", pBuf[i]);
    }
    printf("\n");
}
string GetBinaryStringFromHexString(string strHex)
{
    string sReturn = "";
    unsigned int len = strHex.length();
    for (unsigned int i = 0; i < len; i++)
    {
        switch (strHex[i])
        {
        case '0': sReturn.append("0000"); break;
        case '1': sReturn.append("0001"); break;
        case '2': sReturn.append("0010"); break;
        case '3': sReturn.append("0011"); break;
        case '4': sReturn.append("0100"); break;
        case '5': sReturn.append("0101"); break;
        case '6': sReturn.append("0110"); break;
        case '7': sReturn.append("0111"); break;
        case '8': sReturn.append("1000"); break;
        case '9': sReturn.append("1001"); break;
        case 'A': sReturn.append("1010"); break;
        case 'B': sReturn.append("1011"); break;
        case 'C': sReturn.append("1100"); break;
        case 'D': sReturn.append("1101"); break;
        case 'E': sReturn.append("1110"); break;
        case 'F': sReturn.append("1111"); break;
        }
    }
    return sReturn;
}




int main(void)
{
    //TA初始化阶段
    int rc = 0;
    int nid = 0;
    EC_KEY* key = NULL;
    EC_GROUP* group = NULL;
    EC_builtin_curve* curves = NULL;
    int crv_len = 0;
    int key_size = 0;
    unsigned int sign_len = 0;
    // unsigned char message[] = "abcdefghijklmnopqrstuvwxy";

    BIGNUM* p, * a, * b, * gx, * gy, * z;
    p = BN_new();
    a = BN_new();
    b = BN_new();
    gx = BN_new();
    gy = BN_new();
    z = BN_new();
    BN_CTX* ctx = NULL;
    ctx = BN_CTX_new();

    /* 构造EC_KEY数据结构 */
    key = EC_KEY_new();
    if (key == NULL) {
        printf("EC_KEY_new err.\n");
        return 0;
    }

    /* 获取实现的椭圆曲线个数 */
    crv_len = EC_get_builtin_curves(NULL, 0);
    curves = (EC_builtin_curve*)calloc(sizeof(EC_builtin_curve) * crv_len, 1);
    EC_get_builtin_curves(curves, crv_len);


#if 0
    for (int i = 0; i < crv_len; i++) {
        printf("***** %d *****\n", i);
        printf("nid = %d\n", curves[i].nid);
        printf("comment = %s\n", curves[i].comment);
    }
#endif   

    /* 选择一种椭圆曲线 */
    nid = OBJ_sn2nid("SM2");

    /* 根据选择的椭圆曲线生成密钥参数 group */
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        printf("EC_GROUP_new_by_curve_name err!\n");
        return -1;
    }
    EC_GROUP_get_curve_GFp(group, p, a, b, ctx);        //输出参数p,a,b
    printf("p:%s \n", BN_bn2hex(p));
    printf("a:%s \n", BN_bn2hex(a));
    printf("b:%s \n", BN_bn2hex(b));
    cout << endl;


    EVP_PKEY* pkey = NULL;
    EC_KEY* ec_key = NULL;

    // verify, 第一个参数同sign
    

    BIO* key_2 = NULL;
    key_2 = BIO_new_file("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\TA_public.key", "r"); //读取TA公钥
    pkey = PEM_read_bio_PUBKEY(key_2, NULL, 0, NULL);
    ec_key = EVP_PKEY_get0_EC_KEY(pkey);

   

    ifstream infile;
    infile.open("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\TA_gama_d.txt", ios::in);//读取TA_gama_d
    //ios::in	输入：文件将允许输入操作。如果文件不存在，打开将失败

    string u_gama_s;
    
    infile >> u_gama_s;
    char* u_gama_c = new char[u_gama_s.length()];
    strcpy(u_gama_c, u_gama_s.c_str());
    cout << "2" << endl;
    /*
     string str;
    while (getline(infile, str))
    {
        cout << str << endl;;

    strcpy(gama, str.c_str());
    }
    */
    cout << u_gama_c << endl;
    infile.close();

    BIGNUM* u_gama;
    u_gama = BN_new();
    BN_hex2bn(&u_gama, u_gama_c);

    //计算哈希
    //hash计算
    unsigned char hash_data[20] = { 0 };
    unsigned char sign[256] ;
    SHA1((const unsigned char*)BN_bn2hex(u_gama), strlen(BN_bn2hex(u_gama)), hash_data);
    cout << "hash_data:" << endl;
    printHex(hash_data, 20);
    cout << endl;
   /*
   infile.open("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\TA_sign.txt",ios::in);//读取签名
    //ios::in	输入：文件将允许输入操作。如果文件不存在，打开将失败
    infile >> sign;
    infile.close();
   */
    
 
   
    BIO* sig = NULL;
    
    sig = BIO_new_file("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\text.txt", "rb");  //duqu
    sign_len=BIO_read(sig,sign,256);
    printHex(sign, sign_len);
    cout <<"sign len:"<< sign_len << endl;
   
    
    rc = ECDSA_verify(0, hash_data, 20, sign, sign_len, ec_key);
    if (rc != 1) {
        printf("ECDSA_verify err.\n");
        
    }
    else {
        printf("verify success.\n");
    }
    cout << endl;
    
    //用户读取自身域密钥，计算kd
  
    infile.open("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\User_sk.txt", ios::in);//读取sk
    //ios::in	输入：文件将允许输入操作。如果文件不存在，打开将失败
    
    
    string sk_str = ReadLine("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\User_sk.txt", 1);   //假设用户1
    cout << sk_str << endl;


    BIGNUM *u_kd,*sk;
    u_kd = BN_new();
    sk = BN_new();
    char* sk_c = new char[256];
    strcpy(sk_c, sk_str.c_str());
    BN_hex2bn(&sk,sk_c);
    BN_mod(u_kd, u_gama,  sk, ctx);
    cout << BN_bn2hex(u_kd) << endl;


 ///用户存储计算得出的kd
    ofstream outfile;
    outfile.open("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_kd.txt", ios::out);//存私钥。txt
    //ios::out	输出：文件将允许输出操作。如果文件不存在，则创建一个给定名称的空文件
    outfile << BN_bn2hex(u_kd);
    outfile << ends;
    outfile << endl;
    outfile.close();
    

    //生成5000个随机数r，作为5000个用户的初始广播匿名
    EC_POINT* ID = NULL;
    ID = EC_POINT_new(group);
    BIGNUM* ri;
    ri = BN_new();
    EC_POINT* W = NULL;
    W = EC_POINT_new(group);
    BIGNUM* w;
    w = BN_new();

    string path ;
    for (int i = 0; i < 5000; i++) {
        path = "C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_" + to_string(i)+"_ri.txt";
        BN_rand_range(ri, EC_GROUP_get0_order(group));
        outfile.open(path, ios::out);                                                     //存ri。txt...................
        outfile << BN_bn2hex(ri);
        outfile << ends;
        outfile << endl;
        outfile.close();

        path = "C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_" + to_string(i) + "_ID.txt";
        EC_POINT_mul(group, ID, ri, NULL, NULL, ctx);
        outfile.open(path, ios::out);                                                     //存ID。txt.................
        outfile << EC_POINT_point2hex(group, ID, POINT_CONVERSION_UNCOMPRESSED, ctx);
        outfile << ends;
        outfile << endl;
        outfile.close();


        path = "C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_" + to_string(i) + "_w.txt";
        BN_rand_range(w, EC_GROUP_get0_order(group));
        outfile.open(path, ios::out);                                                     //存ri。txt...................
        outfile << BN_bn2hex(w);
        outfile << ends;
        outfile << endl;
        outfile.close();

        path = "C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_" + to_string(i) + "_Ww.txt";
        EC_POINT_mul(group, W, w, NULL, NULL, ctx);
        outfile.open(path, ios::out);                                                     //存ID。txt.................
        outfile << EC_POINT_point2hex(group, W, POINT_CONVERSION_UNCOMPRESSED, ctx);
        outfile << ends;
        outfile << endl;
        outfile.close();

    }
   


    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_key);

    EC_GROUP_free(group), group = NULL;
    EC_KEY_free(key), key = NULL;

    BN_CTX_free(ctx);
    BN_free(p);//BIGNUM* p, * a, * b, * gx, * gy, * z;* pri_key,sk[n],sigma_g,* x[n],*rm,*y[n],* u, * xxxx[n]
    BN_free(a);
    BN_free(b);
    BN_free(gx);
    BN_free(gy);
    BN_free(z);

    
    return 0;


}
