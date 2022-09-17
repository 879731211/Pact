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

#include <bitset>
#include <windows.h>　

#include <chrono>
#define random(a,b) (rand()%(b-a)+a)
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
string CurrentDate()
{
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    char buf[100] = { 0 };
    std::strftime(buf, sizeof(buf), "%Y-%m-%d-%H-%M-%S", std::localtime(&now));
    return buf;
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


    //计时
    LARGE_INTEGER AIDM_s, AIDM_e, AIDM_tc, SVOM_s, SVOM_e, SVOM_tc, BVMM_s, BVMM_e, BVMM_tc;

    //TA读取自身私钥公钥
    EVP_PKEY* pkey = NULL;
    EC_KEY* ec_key = NULL;


    BIO* key_2 = NULL;
    key_2 = BIO_new_file("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\TA_public.key", "r"); //读取TA公钥
    pkey = PEM_read_bio_PUBKEY(key_2, NULL, 0, NULL);
    ec_key = EVP_PKEY_get0_EC_KEY(pkey);

    const EC_POINT* pub_key = NULL;
    pub_key = EC_KEY_get0_public_key(ec_key);
   


    BIO* key_1 = NULL;
    key_1 = BIO_new_file("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\TA_private.key", "r");  ///读取TA私钥
    pkey = PEM_read_bio_PrivateKey(key_1, NULL, 0, NULL);
    ec_key = EVP_PKEY_get0_EC_KEY(pkey);

    const BIGNUM* pri_key = EC_KEY_get0_private_key(ec_key);
    printf("priv_key:%s \n", BN_bn2hex(pri_key));
    
    //读取用户上传相遇信息  ,,假设用户2确诊 ，上传用户1发来的相遇信息

    string ID_1met2 = ReadLine("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_2_EH\\ID_1met_2.txt", 1);
 //   cout << "ID_1met2:" << ID_1met2 << endl;

    string id_1met2_1 = ReadLine("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_2_EH\\ID_1met_2.txt", 2);
  //  cout << "id_1met2_1:" << id_1met2_1 << endl;

    string id_1met2_2 = ReadLine("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_2_EH\\ID_1met_2.txt", 3);
    // cout << "T:" << T << endl;
  

    string T = ReadLine("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_2_EH\\ID_1met_2.txt", 4);
   // cout << "T:" << T << endl;

    string sign_str = ReadLine("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_2_EH\\ID_1met_2.txt", 5);
  //  cout << "sign_str：" << sign_str << endl;



    string r_kpub = ReadLine("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_2met1_upload.txt", 1);
  //  cout << "r_kpub:" << r_kpub << endl;

    string r_w = ReadLine("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_2met1_upload.txt", 2);
    cout << "r_w" << r_w << endl;

    string id1 = ReadLine("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_2met1_upload.txt", 3);
  //  cout << "id1:" << id1 << endl;

    string id2 = ReadLine("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_2met1_upload.txt", 4);
  //  cout << "id2:" << id2 << endl;

    BIGNUM* sign;
    sign = BN_new();
    char* sign_c = new char[sign_str.length()];
    strcpy(sign_c, sign_str.c_str());
    BN_hex2bn(&sign, sign_c);


    //获取用户相遇匿名第一部分
    char* id_1met2_1_c = new char[id_1met2_1.length()];
    strcpy(id_1met2_1_c, id_1met2_1.c_str());
    EC_POINT* ID_1met2_1 = NULL;
    ID_1met2_1 = EC_POINT_new(group);
    EC_POINT_hex2point(group, id_1met2_1_c, ID_1met2_1, ctx);
  //  cout << "ID_1met2_1" << EC_POINT_point2hex(group, ID_1met2_1, POINT_CONVERSION_COMPRESSED, ctx);///无法输出




    char* id1_c = new char[id1.length()];
    strcpy(id1_c, id1.c_str());
    EC_POINT* ID1 = NULL;
    ID1 = EC_POINT_new(group);
    EC_POINT_hex2point(group, id1_c, ID1, ctx);
    

    char* id2_c = new char[id2.length()];
    strcpy(id2_c, id2.c_str());
    EC_POINT* ID2 = NULL;
    ID2 = EC_POINT_new(group);
    EC_POINT_hex2point(group, id2_c, ID2, ctx);

    char* r_w_c = new char[r_w.length()];
    strcpy(r_w_c, r_w.c_str());
    EC_POINT* r_W = NULL;
    r_W = EC_POINT_new(group);
    EC_POINT_hex2point(group, r_w_c, r_W, ctx);




    char* r_kpub_c = new char[r_kpub.length()];
    strcpy(r_kpub_c, r_kpub.c_str());
    EC_POINT* r_Kpub = NULL;
    r_Kpub = EC_POINT_new(group);
    EC_POINT_hex2point(group, r_kpub_c, r_Kpub, ctx);

    //验证左右等式是否相等

    EC_POINT* equation_left = NULL;
    EC_POINT* equation_right = NULL;

    equation_left = EC_POINT_new(group);
    equation_right = EC_POINT_new(group);


    //计算alpha和beta的值


    //计算阿尔法
    char* ID_1met2_char = new char[ID_1met2.length()];
    strcpy(ID_1met2_char, ID_1met2.c_str());
    unsigned char hash_ID_1met2[20] = { 0 };
    SHA1((const unsigned char*)ID_1met2_char, strlen(ID_1met2_char), hash_ID_1met2);
    BIGNUM* alpha = BN_new();
    BN_bin2bn(hash_ID_1met2, 20, alpha);


    //计算贝塔

    ID_1met2 = ID_1met2.substr(0, ID_1met2.length() - 1);
    string ID_1met2_T = ID_1met2 + T;
    char* ID_1met2_T_char = new char[ID_1met2_T.length()];
    strcpy(ID_1met2_T_char, ID_1met2_T.c_str());
    unsigned char hash_ID_1met2_T[20] = { 0 };
    SHA1((const unsigned char*)ID_1met2_T_char, strlen(ID_1met2_T_char), hash_ID_1met2_T);
    BIGNUM* beta = BN_new();
    BN_bin2bn(hash_ID_1met2_T, 20, beta);

    
    

    //左等式
    EC_POINT_mul(group, equation_left, NULL, ID2, sign, ctx);

   

    //右等式

    EC_POINT_mul(group, r_W, NULL, r_W, beta, ctx);
   

    EC_POINT_mul(group, r_Kpub, NULL, r_Kpub, alpha, ctx);
    EC_POINT_add(group, equation_right, r_W, ID_1met2_1, ctx);



    EC_POINT_add(group, equation_right, equation_right, r_Kpub, ctx);



    if (!EC_POINT_cmp(group, equation_right, equation_left, ctx)) {
        cout << "TA verify success" << endl;
    }
    else {
        cout << "TA verify fail" << endl;
    }



    //TA去匿名
    EC_POINT* s_ID1 = NULL;
    s_ID1 = EC_POINT_new(group);
    EC_POINT_mul(group, s_ID1, NULL, ID1, pri_key, ctx);

    const unsigned char* id_h = (const unsigned char*)(EC_POINT_point2hex(group, s_ID1, POINT_CONVERSION_COMPRESSED, ctx));
    unsigned char hash_idh[20] = { 0 };
    SHA1(id_h, strlen((char*)id_h), hash_idh);

    //hash字符数组转成大数
    BIGNUM* idh = BN_new();
    BN_bin2bn(hash_idh, 20, idh);

    //将hash的大数形式转成二进制
    string bf = GetBinaryStringFromHexString(BN_bn2hex(idh));

    int* intbf = new int[bf.length()];
    for (int i = 0; i < bf.length(); i++) {
        intbf[i] = bf[i] - '0';
    }

    cout << "01字符串:" << id_1met2_2 << endl;
   // id_1met2_2 = id_1met2_2.substr(0, ID_1met2.length() - 2);
    

    id_1met2_2 = id_1met2_2.substr(0, id_1met2_2.length() - 1);
    int* id_1met2_2_bo = new int[id_1met2_2.length()];
    cout <<"first:"<< id_1met2_2.length() << endl;
  
  
    for (int i = 0; i < id_1met2_2.length(); i++) {
        id_1met2_2_bo[i] = id_1met2_2[i] - '0';

    }

    int* rid_bo = new int[id_1met2_2.length()];
    for (int k = 0; k < id_1met2_2.length(); k++) {
        rid_bo[k] = intbf[k] ^ id_1met2_2_bo[k];
    }

    cout << "TA trace the RID:" << endl;
    for (int k = 0; k < id_1met2_2.length(); k++) {
        cout<<rid_bo[k];
    }
    cout << endl;
 


    EC_GROUP_free(group), group = NULL;


    BN_CTX_free(ctx);
    BN_free(p);//BIGNUM* p, * a, * b, * gx, * gy, * z;* pri_key,sk[n],sigma_g,* x[n],*rm,*y[n],* u, * xxxx[n]
    BN_free(a);
    BN_free(b);
    BN_free(gx);
    BN_free(gy);
    BN_free(z);



    return 0;


}
