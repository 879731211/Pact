#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include <string>

#include <windows.h>　

#define random(a,b) (rand()%(b-a)+a)
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
    EC_POINT_get_affine_coordinates_GFp(group, pub_key, gx, gy, NULL);
    printf("pub_key_x:%s \n", BN_bn2hex(gx));
    printf("pub_key_y:%s \n", BN_bn2hex(gy));
    cout << endl;

    printf("p_size:%d", BN_num_bits(p));
    cout << endl;
    
    //cout << "prikey_bit:" << BN_num_bits(p) << endl;

    //计算用户域密钥
    //BIGNUM* sk1, * sk2, * sk3;
    const int n = 5;
    BIGNUM* sk[n];  //
    BIGNUM* SK;
    SK = BN_new();
    for (int i = 0; i < n; i++) {
        sk[i] = BN_new();
        BN_generate_prime(sk[i], 256, 1, NULL, NULL, NULL, NULL);
        printf("sk%d",i);
        printf(" : % s \n", BN_bn2hex(sk[i]));
    }
    cout << endl;

    //找出最小sk
    BIGNUM* min;
    min = BN_new();
    min = sk[0];
    for (int i = 1; i < n; i++) {

        if (BN_cmp(min, sk[i]) == 1)  min = sk[i];

    }
    /*
    * sk1 = BN_new();
    sk2 = BN_new();
    sk3 = BN_new();
    sk1 = BN_generate_prime(sk1, 256, 1, NULL, NULL, NULL, NULL);/////ski > ri ，不然没法求不出来ri，那ski的参数要怎么设置呢？
    sk2 = BN_generate_prime(sk2, 256, 1, NULL, NULL, NULL, NULL);
    sk3 = BN_generate_prime(sk3, 256, 1, NULL, NULL, NULL, NULL);
    printf("sk1:%s \n", BN_bn2hex(sk1));
    printf("sk2:%s \n", BN_bn2hex(sk2));
    printf("sk3:%s \n", BN_bn2hex(sk3));
     */
    

    //sigma,xi,yi.
    BIGNUM* sigma_g;   //
    sigma_g = BN_new();
    
    BN_mul(sigma_g, sk[0], sk[1], ctx);
    for (int i = 2; i < n; i++) {
        BN_mul(sigma_g, sigma_g, sk[i], ctx);
    }
    printf("sigma_g:%s \n", BN_bn2hex(sigma_g));
    cout << endl;
    /*
    BN_mul(sigma, sk1, sk2, ctx1);
    //printf("sigma:%s \n", BN_bn2hex(sigma));
    BN_mul(sigma, sigma, sk3, ctx1);
    printf("sigma:%s \n", BN_bn2hex(sigma));
    */
    

    BIGNUM* x[n],*rm,*y[n];    
    for (int i = 0; i < n; i++) {
        x[i] = BN_new();
        y[i] = BN_new();
    }
    rm = BN_new();
    for (int i = 0; i < n; i++) {
        BN_div(x[i], rm, sigma_g, sk[i], ctx);
        BN_mod_inverse(y[i], x[i], sk[i], ctx);
        printf("x%d", i);
        printf(":%s\n", BN_bn2hex(x[i]));
        printf("y%d", i);
        printf(":%s\n", BN_bn2hex(y[i]));
        
        
        cout << endl;
    }

    /*
    BN_div(x1, rm, sigma, sk1, ctx1);
    printf("x1:%s \n", BN_bn2hex(x1));
    // printf("rm:%s \n", BN_bn2hex(rm));

    BN_div(x2, rm, sigma, sk2, ctx1);
    //printf("rm:%s \n", BN_bn2hex(rm));

    BN_div(x3, rm, sigma, sk3, ctx1);
    //printf("rm:%s \n", BN_bn2hex(rm));
    */

    /*
    BIGNUM* y1, * y2, * y3;
    y1 = BN_new();
    y2 = BN_new();
    y3 = BN_new();
    BN_mod_inverse(y1, x1, sk1, ctx);
    BN_mod_inverse(y2, x2, sk2, ctx);
    BN_mod_inverse(y3, x3, sk3, ctx);
    */
    
    //u
    BIGNUM* u, * xxxx[n];  
    u = BN_new();
    
    for (int i = 0; i < n ; i++) {
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
    
    printf("u:%s \n", BN_bn2hex(u));
    cout << endl;
    /*
    
    */
    BIGNUM* kd;
    kd = BN_new();
    //BN_dec2bn(&kd, "30");
    BN_rand_range(kd, min);
    printf("kd:%s \n", BN_bn2hex(kd));
    cout << endl;

    //计算域公密钥
    BIGNUM* gama_d;
    gama_d = BN_new();
    BN_mul(gama_d, kd, u, ctx);
    printf("gama:%s \n", BN_bn2hex(gama_d));
    cout << endl;

    //用户计算阶段
    //用户计算公密钥
    BIGNUM* u_kd;
    u_kd = BN_new();
    for (int i = 0; i < n; i++) {
        BN_mod(u_kd, gama_d, sk[i], ctx);
        printf("user_kd %d", i);
        printf(":%s\n", BN_bn2hex(u_kd));
    }
    
    cout << endl;

    //K_pub生成
    EC_POINT* K_pub = NULL;
    K_pub = EC_POINT_new(group);
    EC_POINT_mul(group, K_pub, kd, NULL, NULL, ctx);


    //TA对gama_d签名，用户验证
    //hash计算
    unsigned char hash_data[20] = { 0 };
    unsigned char sign[256] = { 0 };
    SHA1((const unsigned char*)BN_bn2hex(gama_d), strlen(BN_bn2hex(gama_d)), hash_data);

    //输出hash值
    printf("hash_data:");
    printHex(hash_data, 20);

    // sign. 第一个参数0,该参数忽略．
    rc = ECDSA_sign(0, hash_data, 20, sign, &sign_len, key);
    if (rc != 1) {
        printf("ECDSA_sign err.\n");
        return 0;
    }
    


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

    // verify, 第一个参数同sign
    rc = ECDSA_verify(0, hash_data, 20, sign, sign_len, key);
    if (rc != 1) {
        printf("ECDSA_verify err.\n");
        return 0;
    }
    else {
        printf("verify success.\n");
    }
    cout << endl;

    //计时
    LARGE_INTEGER AIDM_s, AIDM_e, AIDM_tc, SVOM_s, SVOM_e, SVOM_tc, BVMM_s, BVMM_e, BVMM_tc;
    

    //批处理和单个处理的区别。m=1(单个处理）  m=0(批处理)
    
    int m = 1;
    if (m == 1) {

        //AIDM计时开始
        QueryPerformanceFrequency(&AIDM_tc);
        QueryPerformanceCounter(&AIDM_s);
        //匿名生成ID_1
        EC_POINT* ID_1 = NULL;
        ID_1 = EC_POINT_new(group);
        BIGNUM* ri;
        ri = BN_new();                                   
        BN_rand_range(ri, EC_GROUP_get0_order(group));     ///耗时长1ms 

        EC_POINT_mul(group, ID_1, ri, NULL, NULL, ctx);
        char* id_1 = (EC_POINT_point2hex(group, ID_1, POINT_CONVERSION_COMPRESSED, ctx));

        
        //cout << "id_1:" << id_1 << endl;             //输出耗时1ms
        
        string id_1_str = GetBinaryStringFromHexString(id_1);///////////////////耗时长0.7ms     结构体可以省略
       // cout << "id_1_str:" << id_1_str << endl;            //输出耗时1ms
       
        //匿名生成ID_2
        
        //RID
        const char RID[] = "15918562471";
        BIGNUM* rid = BN_new();
        BN_dec2bn(&rid, RID);

        //printf("RID:%s \n", BN_bn2dec(rid));
        //printf("RID:%s \n", BN_bn2hex(rid));

    
        
        string af = GetBinaryStringFromHexString(BN_bn2hex(rid));
       
        cout << "USER's RID:" << endl;              //输出耗时多1ms-4ms
        cout << af << endl;
       
        //RID字符串转成int数组方便异或
        int* intaf = new int[af.length()];
        for (int i = 0; i < af.length(); i++) {
            intaf[i] = af[i] - '0';
        }
        
  
        //id中的哈希部分
        EC_POINT* ID_h = NULL;
        ID_h = EC_POINT_new(group);
        
        EC_POINT_mul(group, ID_h, NULL, pub_key, ri, ctx);
        

        const unsigned char* id_h = (const unsigned char*)(EC_POINT_point2hex(group, ID_h, POINT_CONVERSION_COMPRESSED, ctx));

       // printf("id_h:%s \n", id_h);
        
        //hash 1计算
        unsigned char hash_idh[20] = { 0 };
        SHA1(id_h, strlen((char*)id_h), hash_idh);
       // printf("hash_id:");
       // printHex(hash_idh, 20);      ////此处耗时1ms

        //hash字符数组转成大数
        BIGNUM* idh = BN_new();
        BN_bin2bn(hash_idh, 20, idh);
        //printf("hash_id:%s \n", BN_bn2hex(idh));
        // 
      
          
        //将hash的大数形式转成二进制
        string bf = GetBinaryStringFromHexString(BN_bn2hex(idh));   

        
       // cout << "bf:" << bf << endl;           ///输出耗时1ms
        
        
        int* intbf = new int[bf.length()];
        for (int i = 0; i < bf.length(); i++) {
            intbf[i] = bf[i] - '0';
        }
        

        //RID与hash的异或
        int* id_2 = new int[af.length()];
        for (int i = 0; i < af.length(); i++) {
            id_2[i] = intbf[i] ^ intaf[i];
        }


        //id_2的string形式 
        std::string id_2_str;
        for (int i = 0; i < af.length(); i++) {
            id_2_str = id_2_str + std::to_string(id_2[i]);            ///耗时0.6ms      结构体能省去
        }
       
       // cout << "id_2_str;" << id_2_str << endl;
        
        //匿名签名生成
            //匿名ID=id_1||id_2
        string ID = id_1_str + id_2_str;
        
        //匿名签名

        char* ID_char = new char[ID.length()];
        strcpy(ID_char, ID.c_str());
        unsigned char hash_ID[20] = { 0 };
        SHA1((const unsigned char*)ID_char, strlen(ID_char), hash_ID);
        
       // printf("hash_ID:");
       // printHex(hash_ID, 20);      ///此处输出耗时1ms
        //hash字符数组转成大数


        BIGNUM* hash_ID_BN = BN_new();
        BN_bin2bn(hash_ID, 20, hash_ID_BN);
        BIGNUM* kd_ri = BN_new();
        BN_add(kd_ri, u_kd, ri);   ///////***u_kd-----kd
        

        BIGNUM* deta = BN_new();
        BN_mod_mul(deta, hash_ID_BN, kd_ri, EC_GROUP_get0_order(group), ctx);
        
        //AIDM计时结束
        QueryPerformanceCounter(&AIDM_e);
        double time_1 = (double)(AIDM_e.QuadPart - AIDM_s.QuadPart) / (double)AIDM_tc.QuadPart * 1000;
        cout << "单个匿名生成和签名 time = " << time_1 << "ms" << endl;
        

        //安全性验证
        BIGNUM* sub = BN_new();
        BIGNUM* mul = BN_new();
        BIGNUM* inverse = BN_new();
        BIGNUM* ceshi = BN_new();
        EC_POINT* ceshi_ID_1 = NULL;
        ceshi_ID_1 = EC_POINT_new(group);
        BN_mod_inverse(inverse, hash_ID_BN, EC_GROUP_get0_order(group), ctx);
        BN_mul(mul, hash_ID_BN, u_kd,ctx);
        BN_sub(sub, deta,mul );
        BN_mul(ceshi, inverse, sub,ctx);
        EC_POINT_mul(group, ceshi_ID_1, NULL, pub_key, ceshi, ctx);
        EC_POINT* ceshi_ID_2 = NULL;
        ceshi_ID_2 = EC_POINT_new(group);
        EC_POINT_mul(group, ceshi_ID_2, NULL, ID_1, pri_key, ctx);


        if (!EC_POINT_cmp(group, ceshi_ID_1, ceshi_ID_2, ctx)) {
            cout << "测试成功" << endl;
        }
        else {
            cout << "测试失败" << endl;
        }
        /*/*/
        
        //匿名签名认证

        //SVOM计时开始
        QueryPerformanceFrequency(&SVOM_tc);
        QueryPerformanceCounter(&SVOM_s);
        EC_POINT* deta_verify_1 = NULL;
        deta_verify_1 = EC_POINT_new(group);
        EC_POINT_mul(group, deta_verify_1, deta, NULL, NULL, ctx);   //  T_em

        EC_POINT* deta_verify_2 = NULL;
        deta_verify_2 = EC_POINT_new(group);
        

        EC_POINT* deta_verify_mid = NULL;
        deta_verify_mid = EC_POINT_new(group);
        EC_POINT_add(group, deta_verify_mid, K_pub, ID_1, ctx);         //  T_ea
        EC_POINT_mul(group, deta_verify_2, NULL, deta_verify_mid, hash_ID_BN, ctx);        //  T_em

        /*
        
        EC_POINT* h_Kpub = NULL;
        h_Kpub = EC_POINT_new(group);
        EC_POINT* h_ID_1 = NULL;
        h_ID_1 = EC_POINT_new(group);
        EC_POINT_mul(group, h_Kpub, NULL, K_pub, hash_ID_BN, ctx);       //另一个方法如果两个 哈希值 不一样，但是我假设好像是一样的，这样子似乎效率更加高，但不清楚有没有安全隐患
        EC_POINT_mul(group, h_ID_1, NULL, ID_1, hash_ID_BN, ctx);
        EC_POINT_add(group, deta_verify_2, h_Kpub, h_ID_1, ctx);

        */


        if (!EC_POINT_cmp(group, deta_verify_1, deta_verify_2, ctx)) {
            cout << "anomity verify success" << endl;
        }
        else {
            cout << "anomity verify fail" << endl;
        }

        //SVOM计时结束
        QueryPerformanceCounter(&SVOM_e);
        double time_2 = (double)(SVOM_e.QuadPart - SVOM_s.QuadPart) / (double)SVOM_tc.QuadPart * 1000;
        cout << "单个匿名验证 time = " << time_2 << "ms" << endl;

        //政府匿名追踪
        EC_POINT* ID_h_trace = NULL;
        ID_h_trace = EC_POINT_new(group);
        EC_POINT_mul(group, ID_h_trace, NULL, ID_1, pri_key, ctx);
        const unsigned char* id_h_trace = (const unsigned char*)(EC_POINT_point2hex(group, ID_h_trace, POINT_CONVERSION_COMPRESSED, ctx));////

        //政府计算哈希
        unsigned char hash_idh_trace[20] = { 0 };
        SHA1(id_h_trace, strlen((char*)id_h_trace), hash_idh_trace);
        //hash字符数组转成大数
        BIGNUM* idh_trace = BN_new();
        BN_bin2bn(hash_idh_trace, 20, idh_trace);
        //将hash的大数形式转成二进制
        string h_trace = GetBinaryStringFromHexString(BN_bn2hex(idh_trace));
        cout << "h_trace:" << h_trace << endl;
        int* int_h_trace = new int[h_trace.length()];
        for (int i = 0; i < h_trace.length(); i++) {
            int_h_trace[i] = h_trace[i] - '0';
        }
        int* RID_trace = new int[af.length()];
        for (int i = 0; i < af.length(); i++) {
            RID_trace[i] = id_2[i] ^ int_h_trace[i];
        }
        cout << "TA trace the RID:" << endl;
        for (int i = 0; i < af.length(); i++) {
            cout << RID_trace[i];
        }
        cout << "af length()" << af.length();
        cout << endl;

        BN_free(ri);
    }
    if(m==0) {
    //匿名生成ID_1            ,批处理用户生成
        const int batch = 10;
        EC_POINT* ID_1[batch];
        char* id_1[batch];
        BIGNUM* ri[batch];
        string id_1_str[batch];
        for (int i = 0; i < batch; i++) {
            ri[i] = BN_new();
            ID_1[i] = EC_POINT_new(group);
            BN_rand_range(ri[i], EC_GROUP_get0_order(group));
            EC_POINT_mul(group, ID_1[i], ri[i], NULL, NULL, ctx);
            id_1[i] = EC_POINT_point2hex(group, ID_1[i], POINT_CONVERSION_COMPRESSED, ctx);
            printf("id_1[%d", i);
            printf("]%s\n", id_1[i]);
           // cout << "id_1[]:" << id_1[i] << endl;
            id_1_str[i] = GetBinaryStringFromHexString(id_1[i]);///////////////////
            cout << "id_1_str[" << i;
            cout << "]:" << id_1_str[i] << endl;
            cout << endl;
        }


    //匿名生成ID_2

    //RID
        const char RID[] = "15918562471";
        BIGNUM* rid = BN_new();
        BN_dec2bn(&rid, RID);

    //printf("RID:%s \n", BN_bn2dec(rid));
    //printf("RID:%s \n", BN_bn2hex(rid));
        string rid_str = GetBinaryStringFromHexString(BN_bn2hex(rid));
        cout << "USER's RID:"<<rid_str << endl;
        cout << endl;
    //RID字符串转成int数组方便异或
        int* int_rid_str = new int[rid_str.length()];
        for (int i = 0; i < rid_str.length(); i++) {
            int_rid_str[i] = rid_str[i] - '0';
            //cout << int_rid_str[i];
        }
        
    //id中的哈希部分
        EC_POINT* ID_h[batch];
        char* id_h[batch];
        for (int i = 0; i < batch; i++) {
            ID_h[i] = EC_POINT_new(group);
            EC_POINT_mul(group, ID_h[i], NULL, pub_key, ri[i], ctx);
            id_h[i] = EC_POINT_point2hex(group, ID_h[i], POINT_CONVERSION_COMPRESSED, ctx);
            printf("id_h[%d", i);
            printf("]:%s \n", id_h[i]);
        }


    //hash 1计算
        unsigned char hash_idh[batch][20]={0};
        for (int i = 0; i < batch; i++) {
            SHA1((const unsigned char*)id_h[i], strlen(id_h[i]), hash_idh[i]);
            printf("hash_id[%d",i);
            printf("]:");
            printHex(hash_idh[i], 20);
        }

    //hash字符数组转成大数
        BIGNUM* idh[batch];
        string idh_str[batch];
        int* int_idh_str[batch];
        for (int i = 0; i < batch; i++) {
            idh[i] = BN_new();
            BN_bin2bn(hash_idh[i], 20, idh[i]);
           //将hash的大数形式转成二进制
            idh_str[i] = GetBinaryStringFromHexString(BN_bn2hex(idh[i]));
            cout << "idh_str[" << i ;
            cout << "]:" << idh_str[i] << endl;
            int_idh_str[i] = new int[idh_str[i].length()];
            for (int j = 0; j < idh_str[i].length(); j++) {
                int_idh_str[i][j] = idh_str[i][j] - '0';
            }
            cout << endl;
        }



//RID与hash的异或
        
        int** id_2=new int*[batch];
        for (int i = 0; i < batch; ++i) {
            id_2[i] = new int[rid_str.length()];
            
        }
        for (int i = 0; i < batch; ++i) {
            for (int j = 0; j < rid_str.length(); j++) {
                id_2[i][j] = int_idh_str[i][j] ^ int_rid_str[j];
                cout << id_2[i][j];
            }
            cout << endl;
        }
       
//id_2的string形式
        std::string id_2_str[batch];
        for (int i = 0; i < batch; i++) {
           for (int j = 0; j < rid_str.length(); j++) {
               id_2_str[i] = id_2_str[i] + std::to_string(id_2[i][j]);
            }
            cout << "id_2_str[" << i ;
            cout << "];" << id_2_str[i] << endl;
        }

//匿名签名生成
    //匿名ID=id_1||id_2
        string ID[batch];
        char** ID_char = new char* [batch];
        BIGNUM* hash_ID_BN[batch];
        BIGNUM* kd_ri[batch];
        unsigned char hash_ID[batch][20]={0};
        BIGNUM* deta[batch];
        for (int i = 0; i < batch; i++) {
            ID[i] = id_1_str[i] + id_2_str[i];

            //签名生成
            ID_char[i] = new char[ID[i].length()];
            strcpy(ID_char[i], ID[i].c_str());
            SHA1((const unsigned char*)ID_char[i], strlen(ID_char[i]), hash_ID[i]);
            cout << "hash_ID[" << i;
            printf("]:");
            printHex(hash_ID[i], 20);
    //hash字符数组转成大数
            hash_ID_BN[i] = BN_new();
            BN_bin2bn(hash_ID[i], 20, hash_ID_BN[i]);
            kd_ri[i] = BN_new();
            BN_add(kd_ri[i], u_kd, ri[i]);   ///////***u_kd-----kd
            deta[i] = BN_new();
            BN_mod_mul(deta[i], hash_ID_BN[i], kd_ri[i], EC_GROUP_get0_order(group), ctx);
        }
//批处理向量

        srand((int)time(0));
        int v[batch];
        
        
        BIGNUM* deta_batch = BN_new();

        //BVMM计时开始
        QueryPerformanceFrequency(&BVMM_tc);
        QueryPerformanceCounter(&BVMM_s);

        for (int i = 0; i < batch; i++) {
            v[i] = random(1, 1024);
            BN_mul_word(deta[i], v[i]);                             //n T_BN_M
        }

        BN_add(deta_batch, deta[0], deta[1]);
        for (int i = 2; i < batch; i++) {
            BN_add(deta_batch, deta_batch, deta[i]);                  //n T_BN_A
        }
        

        
        //匿名签名认证
        EC_POINT* deta_verify_1 = NULL;
        deta_verify_1 = EC_POINT_new(group);
        EC_POINT_mul(group, deta_verify_1, deta_batch, NULL, NULL, ctx);/////////  T_em

        EC_POINT* deta_verify_2 = NULL;
        deta_verify_2 = EC_POINT_new(group);
        /////////

        EC_POINT* deta_verify_mid[batch];
        for (int i = 0; i < batch; i++) {
            BN_mul_word(hash_ID_BN[i], v[i]);        //n T_BN_M
        }

        BIGNUM* vi_h_sum;
        vi_h_sum = BN_new();
        BN_add(vi_h_sum, hash_ID_BN[0], hash_ID_BN[1]);     //T_BN_A
        for (int i = 2; i < batch; i++) {
            BN_add(vi_h_sum, vi_h_sum, hash_ID_BN[i]);      //n-2 T_BN_A
        }

        EC_POINT* vi_h_Kpub;
        vi_h_Kpub = EC_POINT_new(group);
        EC_POINT_mul(group, vi_h_Kpub, NULL, K_pub, vi_h_sum, ctx);    //T_em
         
        for (int i = 0; i < batch; i++) {
            deta_verify_mid[i] = EC_POINT_new(group);
            EC_POINT_mul(group, deta_verify_mid[i], NULL, ID_1[i], hash_ID_BN[i], ctx);            //n  T_em
        }
       
        EC_POINT_add(group, deta_verify_2, vi_h_Kpub, deta_verify_mid[0], ctx);     // T_ea
        for (int i = 1; i < batch; i++) {
            EC_POINT_add(group, deta_verify_2, deta_verify_2, deta_verify_mid[i], ctx);     //n-1 T_ea
        }
        
        /*
        
        EC_POINT* deta_verify_mid[batch] ;
        for (int i = 0; i < batch; i++) {
            deta_verify_mid[i]= EC_POINT_new(group);                                    
            EC_POINT_add(group, deta_verify_mid[i], K_pub, ID_1[i], ctx);           //n T_ea
            BN_mul_word(hash_ID_BN[i], v[i]);                                       //n T_BN_M
            EC_POINT_mul(group, deta_verify_mid[i], NULL, deta_verify_mid[i], hash_ID_BN[i], ctx);   //n T_em
        }
        EC_POINT_add(group, deta_verify_2, deta_verify_mid[0], deta_verify_mid[1], ctx);      ///T_ea
        for (int i = 2; i < batch; i++) {
            EC_POINT_add(group, deta_verify_2, deta_verify_2, deta_verify_mid[i], ctx);             //n-2 T_ea
        }
        
        */
        

        if (!EC_POINT_cmp(group, deta_verify_1, deta_verify_2, ctx)) {
            cout << "batch anomity verify success" << endl;
        }
        else {
            cout << "batch anomity verify fail" << endl;
        }

        QueryPerformanceCounter(&BVMM_e);
        double time_3 = (double)(BVMM_e.QuadPart - BVMM_s.QuadPart) / (double)BVMM_tc.QuadPart * 1000;
        cout << "批处理签名验证 time = " << time_3 << "ms" << endl;

        //政府匿名追踪
        EC_POINT* ID_h_trace = NULL;
        ID_h_trace = EC_POINT_new(group);
        EC_POINT_mul(group, ID_h_trace, NULL, ID_1[0], pri_key, ctx);//追踪第一个id
        const unsigned char* id_h_trace = (const unsigned char*)(EC_POINT_point2hex(group, ID_h_trace, POINT_CONVERSION_COMPRESSED, ctx));

        //政府计算哈希
        unsigned char hash_idh_trace[20] = { 0 };
        SHA1(id_h_trace, strlen((char*)id_h_trace), hash_idh_trace);
        //hash字符数组转成大数
        BIGNUM* idh_trace = BN_new();
        BN_bin2bn(hash_idh_trace, 20, idh_trace);
        //将hash的大数形式转成二进制
        string h_trace = GetBinaryStringFromHexString(BN_bn2hex(idh_trace));
        cout << "h_trace:" << h_trace << endl;
        int* int_h_trace = new int[h_trace.length()];
        for (int i = 0; i < h_trace.length(); i++) {
            int_h_trace[i] = h_trace[i] - '0';
        }
        int* RID_trace = new int[rid_str.length()];
        for (int i = 0; i < rid_str.length(); i++) {
            RID_trace[i] = id_2[0][i] ^ int_h_trace[i];
        }
        cout << "TA trace the RID:" << endl;
        for (int i = 0; i < rid_str.length(); i++) {
            cout << RID_trace[i];
        }
        cout << endl;

        for (int i = 0; i < batch; i++) {
            BN_free(ri[i]);
        }
       
}
    
   
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
    
    BN_free(u_kd);
    BN_free(a);

    return 0;
    
   
}
