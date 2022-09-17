#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include <string>
#include <ctime>
#include <windows.h>　
using namespace std;
LARGE_INTEGER AIDM_s, AIDM_e, AIDM_tc;
#define random(a,b) (rand()%(b-a)+a)
void ec_point_small_mul(int num, const EC_POINT* point, EC_POINT* Ec_point, EC_GROUP* group)
{
    int a[100];
    int j = 0;
   
    while (num) {
        a[j] = num % 2;
        num = num / 2;
        j++;
    }
    EC_POINT* ec_point[100];
    ec_point[0] = EC_POINT_new(group);
    EC_POINT_add(group, ec_point[0], ec_point[0], point, NULL);
   
    for (int k = 1; k < j; k++) {
      
        ec_point[k] = EC_POINT_new(group);
        EC_POINT_add(group, ec_point[k], ec_point[k-1], ec_point[k-1],NULL);
    }
    for (int i = 0; i < j; i++) {
        if (a[i] == 1)EC_POINT_add(group, Ec_point, Ec_point, ec_point[i], NULL);
    }
 
}


int main(void) {
  
    int nid = 0;
    EC_GROUP* group = NULL;
    BN_CTX* ctx = NULL;
    ctx = BN_CTX_new();

    /* 选择一种椭圆曲线 */
    nid = OBJ_sn2nid("SM2");

    /* 根据选择的椭圆曲线生成密钥参数 group */
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        printf("EC_GROUP_new_by_curve_name err!\n");
        return -1;
    }
   
    
    
    BIGNUM* ri;
    ri = BN_new();
    BN_rand_range(ri, EC_GROUP_get0_order(group));
    

    
    

    EC_POINT* P1 = NULL;
    P1 = EC_POINT_new(group);
    EC_POINT* P2 = NULL;
    P2 = EC_POINT_new(group);
    

    const int n = 10;
    //点乘 计时开始
    QueryPerformanceFrequency(&AIDM_tc);
    QueryPerformanceCounter(&AIDM_s);
    
    for (int i = 0; i < n; i++) {
        EC_POINT_mul(group, P1, ri, NULL, NULL, ctx);
    }
    
    //点乘 计时结束
    QueryPerformanceCounter(&AIDM_e);
    double time_1 = (double)(AIDM_e.QuadPart - AIDM_s.QuadPart) / (double)AIDM_tc.QuadPart * 1000/n;
    cout << "椭圆曲线点乘 time = " << time_1 << "ms" << endl;



    //点加 计时开始
    QueryPerformanceFrequency(&AIDM_tc);
    QueryPerformanceCounter(&AIDM_s);

    for (int i = 0; i < n; i++) {
        EC_POINT_add(group, P2, P1, P2, ctx);
    }

    //点加 计时结束
    QueryPerformanceCounter(&AIDM_e);
    double time_2 = (double)(AIDM_e.QuadPart - AIDM_s.QuadPart) / (double)AIDM_tc.QuadPart * 1000/n ;
    cout << "椭圆曲线点加 time = " << time_2 << "ms" << endl;
    
    



    unsigned char hash_idh[20] = { 0 };
    const unsigned char * a= (const unsigned char*)"dsad";
    //哈希 计时开始
    QueryPerformanceFrequency(&AIDM_tc);
    QueryPerformanceCounter(&AIDM_s);
    for (int i = 0; i < n; i++) {
        SHA1(a, strlen((const char*)a), hash_idh);
    }
    //哈希 计时结束
    QueryPerformanceCounter(&AIDM_e);
    double time_3 = (double)(AIDM_e.QuadPart - AIDM_s.QuadPart) / (double)AIDM_tc.QuadPart * 1000 / n;
    cout << "哈        希 time = " << time_3 << "ms" << endl;

    


    int v[n];
    BIGNUM* BN;
    BN = BN_new();
    BN_generate_prime(BN, 256, 1, NULL, NULL, NULL, NULL);
   
    BIGNUM* V[n];
    for (int i = 0; i < n; i++) {
        v[i] = random(1, 1024);
        
        V[i] = BN_new();
        BN_dec2bn(&V[i], to_string(v[i]).c_str());
    }

    //小数乘 计时开始
    QueryPerformanceFrequency(&AIDM_tc);
    QueryPerformanceCounter(&AIDM_s);
    for (int i = 0; i < n; i++) {
        BN_mul_word(BN, v[i]);
    }
    //小数乘 计时结束
    QueryPerformanceCounter(&AIDM_e);
    double time_4 = (double)(AIDM_e.QuadPart - AIDM_s.QuadPart) / (double)AIDM_tc.QuadPart * 1000 / n;
    cout << "小数     乘 time = " << time_4 << "ms" << endl;


    //小数点乘 计时开始

    EC_POINT* P3 = NULL;
    P3 = EC_POINT_new(group);
    QueryPerformanceFrequency(&AIDM_tc);
    QueryPerformanceCounter(&AIDM_s);
    
    for (int i = 0; i < n; i++) {
       
        ec_point_small_mul(v[i], EC_GROUP_get0_generator(group), P3, group);
        //cout << EC_POINT_point2hex(group, P3, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;
        P3 = EC_POINT_new(group);
    }
    //小数点乘 计时结束
    QueryPerformanceCounter(&AIDM_e);
    double time_5 = (double)(AIDM_e.QuadPart - AIDM_s.QuadPart) / (double)AIDM_tc.QuadPart * 1000 / n;
    cout << "小数   点乘 time = " << time_5 << "ms" << endl;
    cout<< EC_POINT_point2hex(group, P1, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;

    //ec_point_small_mul(int num, EC_POINT * point, EC_POINT * Ec_point, EC_GROUP * group)

    BN_free(BN);
    BN_free(ri);
    EC_POINT_free(P1);
    EC_POINT_free(P2);
    EC_GROUP_free(group), group = NULL;


    




}

