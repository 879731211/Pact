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


#include <fstream>


#include <windows.h>　

#define random(a,b) (rand()%(b-a)+a)
#define EC_POINT_SIZE 256
extern "C"
{
#include <openssl/applink.c>
}
using namespace std;

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


   



    /* 设置密钥参数 */
    rc = EC_KEY_set_group(key, group);
    if (rc != 1) {
        printf("EC_KEY_set_group err.\n");
        return -1;
    }

    /* 生成密钥 */
    rc = EC_KEY_generate_key(key);
    if (rc != 1) {
        printf("EC_KEY_generate_key err.\n");
        return 0;
    }

    /* 检查密钥 */
    rc = EC_KEY_check_key(key);
    if (rc != 1) {
        printf("check key err.\n");
        return 0;
    }

    //输出密钥大小和私钥
    key_size = ECDSA_size(key);
    printf("key_size = %d\n", key_size);
    const BIGNUM* pri_key = EC_KEY_get0_private_key(key);
    printf("priv_key:%s \n", BN_bn2hex(pri_key));
    const EC_POINT* pub_key = NULL;
    pub_key = EC_KEY_get0_public_key(key);
    EC_POINT_get_affine_coordinates(group, pub_key, gx, gy, NULL);
    printf("pub_key_x:%s \n", BN_bn2hex(gx));
    printf("pub_key_y:%s \n", BN_bn2hex(gy));

    cout << "TA_pub_key:" << EC_POINT_point2hex(group, pub_key, POINT_CONVERSION_COMPRESSED, ctx) << endl;
    cout << endl;
    
    unsigned char buf[65];
    unsigned long buflen = 65;
    EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, buf, buflen, NULL);

    cout << endl;

    //测试biowrite
    EVP_PKEY* pkey = NULL;
    EC_KEY* ec_key = NULL;

    BIO* bio_out = BIO_new_file("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\TA_private.key", "w");
    PEM_write_bio_ECPrivateKey(bio_out, key, NULL, NULL, 0, NULL, NULL);
    BIO_free(bio_out);

    bio_out = BIO_new_file("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\TA_public.key", "w");
    PEM_write_bio_EC_PUBKEY(bio_out, key);
    BIO_free(bio_out);

    
    //

    ofstream outfile;
    



    //cout << "prikey_bit:" << BN_num_bits(p) << endl;

    //计算用户域密钥
    //BIGNUM* sk1, * sk2, * sk3;
    const int n = 5000;
    BIGNUM* sk[n];  //
    BIGNUM* SK;
    SK = BN_new();

    outfile.open("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\User_sk.txt", ios::out);//存用户sk。txt
   //ios::out	输出：文件将允许输出操作。如果文件不存在，则创建一个给定名称的空文件

    for (int i = 0; i < n; i++) {
        sk[i] = BN_new();
        BN_generate_prime(sk[i], 256, 1, NULL, NULL, NULL, NULL);
      //  printf("sk%d", i);
      //  printf(" : % s \n", BN_bn2hex(sk[i]));
        outfile << BN_bn2hex(sk[i]);
        outfile << ends;
        outfile << endl;
    }
    cout << endl;
 
    outfile.close();



    //找出最小sk
    BIGNUM* min;
    min = BN_new();
    min = sk[0];
    for (int i = 1; i < n; i++) {

        if (BN_cmp(min, sk[i]) == 1)  min = sk[i];

    }


     //sigma,xi,yi.
    BIGNUM* sigma_g;   //
    sigma_g = BN_new();

    BN_mul(sigma_g, sk[0], sk[1], ctx);
    for (int i = 2; i < n; i++) {
        BN_mul(sigma_g, sigma_g, sk[i], ctx);
    }
   // printf("sigma_g:%s \n", BN_bn2hex(sigma_g));
    cout << endl;
  


    BIGNUM* x[n], * rm, * y[n];
    for (int i = 0; i < n; i++) {
        x[i] = BN_new();
        y[i] = BN_new();
    }
    rm = BN_new();
    for (int i = 0; i < n; i++) {
        BN_div(x[i], rm, sigma_g, sk[i], ctx);
        BN_mod_inverse(y[i], x[i], sk[i], ctx);
        
    }


    //u
    BIGNUM* u, * xxxx[n];
    u = BN_new();

    for (int i = 0; i < n; i++) {
        xxxx[i] = BN_new();
        BN_mul(xxxx[i], x[i], y[i], ctx);

    }
    BN_add(u, xxxx[0], xxxx[1]);
    for (int i = 2; i < n; i++) {
        BN_add(u, u, xxxx[i]);
    }
    /*
    BN_mul(u, x1, y1, ctx1);
    BN_mul(xxxx, x2, y2, ctx1);
    BN_add(u, u, xxxx);
    BN_mul(xxxx, x3, y3, ctx1);
    BN_add(u, u, xxxx);
    */

  //  printf("u:%s \n", BN_bn2hex(u));
    cout << endl;
    /*

    */
    BIGNUM* kd;
    kd = BN_new();
    //BN_dec2bn(&kd, "30");
    BN_rand_range(kd, min);
  //  printf("kd:%s \n", BN_bn2hex(kd));
    cout << endl;

    //计算域公密钥
    BIGNUM* gama_d;
    gama_d = BN_new();
    BN_mul(gama_d, kd, u, ctx);
 //   printf("gama:%s \n", BN_bn2hex(gama_d));
    cout << endl;

    outfile.open("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\TA_gama_d.txt", ios::out);//存域公钥：kd*u。txt
    //ios::out	输出：文件将允许输出操作。如果文件不存在，则创建一个给定名称的空文件
    outfile << BN_bn2hex(gama_d);
    outfile << ends;
    outfile << endl;
    outfile.close();


    //K_pub生成
    EC_POINT* K_pub = NULL;
    K_pub = EC_POINT_new(group);
    EC_POINT_mul(group, K_pub, kd, NULL, NULL, ctx);

    outfile.open("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\TA_kd.txt", ios::out);//存kd。txt
    //ios::out	输出：文件将允许输出操作。如果文件不存在，则创建一个给定名称的空文件
    outfile << BN_bn2hex(kd);
    outfile << ends;
    outfile << endl;
    outfile.close();


    EC_POINT* K_pub_1 = NULL;
    K_pub_1 = EC_POINT_new(group);
    EC_POINT_point2oct(group, K_pub, POINT_CONVERSION_UNCOMPRESSED, buf, buflen, NULL);
    /*
     EC_POINT_oct2point(group, K_pub_1, buf, buflen, NULL);
    if (EC_POINT_cmp(group, K_pub, K_pub_1, NULL) == 0)cout << "same" << endl;
    将oct转为点
    */
   
    outfile.open("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\TA_K_pub.txt", ios::out);   //存K_pub。txt
    //ios::out	输出：文件将允许输出操作。如果文件不存在，则创建一个给定名称的空文件
    outfile << buf;
    outfile << ends;
    outfile << endl;
    outfile.close();


    //TA对gama_d签名，用户验证
    //hash计算
    unsigned char hash_data[20] = { 0 };
    unsigned char sign[256] = { 0 };
    SHA1((const unsigned char*)BN_bn2hex(gama_d), strlen(BN_bn2hex(gama_d)), hash_data);

    //输出hash值
    printf("hash_data:");
    printHex(hash_data, 20);
    
    outfile.open("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\TA_gama_d_hash.txt", ios::out);   //存K_pub。txt
   //ios::out	输出：文件将允许输出操作。如果文件不存在，则创建一个给定名称的空文件
    outfile << buf;
    outfile << ends;
    outfile << endl;
    outfile.close();

    // sign. 第一个参数0,该参数忽略．

    BIO* key_1 = NULL;
    key_1 = BIO_new_file("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\TA_private.key", "r");
    pkey = PEM_read_bio_PrivateKey(key_1, NULL, 0, NULL);
    ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    BIO_free(key_1);
    rc = ECDSA_sign(0, hash_data, 20, sign, &sign_len, ec_key);
    if (rc != 1) {
        printf("ECDSA_sign err.\n");
        return 0;
    }
    cout << sign_len << endl;
    

    printf("sign success.\n");
    printf("sign:");
    printHex(sign, sign_len);            //输出签名
    const unsigned char* S = sign;
    ECDSA_SIG* signature;
    signature = d2i_ECDSA_SIG(NULL, &S, sign_len);               //签名转换r，s
    const BIGNUM* r = ECDSA_SIG_get0_r(signature);
    const BIGNUM* s = ECDSA_SIG_get0_s(signature);
    printf("sign_r:%s \n", BN_bn2hex(r));
    printf("sign_s:%s \n", BN_bn2hex(s));


    //签名输出测试
    BIO* out = NULL;
    out = BIO_new_file("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\text.txt", "wb");
    int i=BIO_write(out, sign, sign_len);
    cout << "i:" << i << endl;
    //

    BIO_free(out);


    // verify, 第一个参数同sign

    BIO* key_2 = NULL;
    key_2 = BIO_new_file("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\TA_public.key", "r");
    pkey = PEM_read_bio_PUBKEY(key_2,NULL,0,NULL);
    ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    BIO_free(key_2);
    
    EC_GROUP_free(group), group = NULL;
    EC_KEY_free(key), key = NULL;

    BN_CTX_free(ctx);
    BN_free(p);//BIGNUM* p, * a, * b, * gx, * gy, * z;* pri_key,sk[n],sigma_g,* x[n],*rm,*y[n],* u, * xxxx[n]
    BN_free(a);
    BN_free(b);
    BN_free(gx);
    BN_free(gy);
    BN_free(z);

    for (int i = 0; i < n; i++) {
        BN_free(sk[i]);
        BN_free(x[i]);
        BN_free(y[i]);
        BN_free(xxxx[i]);
    }

    BN_free(sigma_g);
    BN_free(rm);
    BN_free(u);
    BN_free(kd);
    BN_free(gama_d);

    
    BN_free(a);
    BN_free(a);
    return 0;


}
