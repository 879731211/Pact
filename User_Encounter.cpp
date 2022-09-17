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
#include <windows.h>��

#include <chrono>
#define random(a,b) (rand()%(b-a)+a)
using namespace std;


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
string IntToString(int& i)
{
    string s;
    stringstream ss(s);
    ss << i;
    return ss.str();
}
int main(void)
{
    //TA��ʼ���׶�
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

    

    /* ��ȡʵ�ֵ���Բ���߸��� */
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

    /* ѡ��һ����Բ���� */
    nid = OBJ_sn2nid("SM2");

    /* ����ѡ�����Բ����������Կ���� group */
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        printf("EC_GROUP_new_by_curve_name err!\n");
        return -1;
    }
    EC_GROUP_get_curve_GFp(group, p, a, b, ctx);        //�������p,a,b
    printf("p:%s \n", BN_bn2hex(p));
    printf("a:%s \n", BN_bn2hex(a));
    printf("b:%s \n", BN_bn2hex(b));
    cout << endl;


    //��ʱ
    LARGE_INTEGER AIDM_s, AIDM_e, AIDM_tc, SVOM_s, SVOM_e, SVOM_tc, BVMM_s, BVMM_e, BVMM_tc;

    //��ȡTA��Կ
    EVP_PKEY* pkey = NULL;
    EC_KEY* ec_key = NULL;

  
    BIO* key_2 = NULL;
    key_2 = BIO_new_file("C:\\Users\\87973\\source\\repos\\Project1\\initial_data\\TA_public.key", "r"); //��ȡTA��Կ
    pkey = PEM_read_bio_PUBKEY(key_2, NULL, 0, NULL);
    ec_key = EVP_PKEY_get0_EC_KEY(pkey);

    const EC_POINT* pub_key = NULL;
    pub_key = EC_KEY_get0_public_key(ec_key);
    cout << "TA_pub_key:"<<EC_POINT_point2hex(group, pub_key, POINT_CONVERSION_COMPRESSED, ctx) << endl;
   



    //�û���������������������  ����û������û�2
        
        //��ȡ����û�����ʹ�õ�ri
    ifstream infile;
    const int user_sum = 400;
    int user_nums[user_sum];
    for (int i = 0; i < user_sum; i++) {
        user_nums[i] = i;
    }
    char ri_c[user_sum][1000] = { 0 };

    for (int i = 0; i < user_sum; i++) {
        infile.open("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_"+to_string(user_nums[i])+"_ri.txt", ios::in);
        infile >> ri_c[i];
        infile.close();
    }
    //infile.open("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_1_ri.txt", ios::in);
    //ios::in	���룺�ļ��������������������ļ������ڣ��򿪽�ʧ��
    //char ri_c[1000] = { 0 };
    
    
    BIGNUM* ri[user_sum];
    for (int i = 0; i < user_sum; i++) {
        ri[i] = BN_new();
        BN_hex2bn(&ri[i], ri_c[i]);
        cout << "user_"+ to_string(user_nums[i])+"_ri:" << BN_bn2hex(ri[i]) << endl;
    }
   
        //���ȶ���û� ��ȡ�����û�����ID�������ȡ�û�2��ID
    EC_POINT* ID = NULL;
    ID = EC_POINT_new(group);
    infile.open("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_2_ID.txt", ios::in);
    //ios::in	���룺�ļ��������������������ļ������ڣ��򿪽�ʧ��
    char u_ID[1000] = { 0 };
    infile >> u_ID;
    EC_POINT_hex2point(group,u_ID,ID,ctx);

    cout << "user_2 ID:" << EC_POINT_point2hex(group, ID, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;
    infile.close();
    cout << endl;

    char w_c[user_sum][1000] = { 0 };
    for (int i = 0; i < user_sum; i++) {
        infile.open("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_" + to_string(user_nums[i]) + "_w.txt", ios::in);//��ȡ����û� w
        infile >> w_c[i];
        infile.close();
    }
    //infile.open("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_1_w.txt", ios::in);//��ȡw
    
    BIGNUM* w[user_sum];
    for (int i = 0; i < user_sum; i++) {
        w[i] = BN_new();
        BN_hex2bn(&w[i], w_c[i]);
        cout << "user_" + to_string(user_nums[i]) + "_ w:" << BN_bn2hex(w[i]) << endl;
        infile.close();
    }
   
    cout << endl;

    infile.open("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_kd.txt", ios::in);//��ȡkd
    char kd_c[1000] = { 0 };
    infile >> kd_c;
    infile.close();

    BIGNUM* kd;
    kd = BN_new();
    BN_hex2bn(&kd, kd_c);
    cout << "kd:" << BN_bn2hex(kd) << endl;

    //��ȡ��������ʱ��
    string T[user_sum];

    

    char* id_1met2_1[user_sum];


    //��������ID=id_1||id_2
    string ID_1met2[user_sum]; 

    string id_2_str[user_sum];
   
    BIGNUM* sign[user_sum]; 

    double ttt=0;
   
    for (int i = 0; i < user_sum; i++) {

        //��i���û���ʱ��
        T[i]= CurrentDate();

      

        //RID
        const char RID[] = "15918562471";
        BIGNUM* rid = BN_new();
        BN_dec2bn(&rid, RID);
       

        string af = GetBinaryStringFromHexString(BN_bn2hex(rid));
        //cout << "USER's RID:" << endl;              //�����ʱ��1ms-4ms
       // cout << af << endl;

        //RID�ַ���ת��int���鷽�����
        int* intaf = new int[af.length()];
        for (int j = 0; j < af.length(); j++) {
            intaf[j] = af[j] - '0';
        }
       

    

        //�û�1��������ID_1met2��
        EC_POINT* ID_1met2_1 = NULL;
        ID_1met2_1 = EC_POINT_new(group);

        EC_POINT_mul(group, ID_1met2_1, NULL, ID, ri[i], ctx);

        id_1met2_1[i] = EC_POINT_point2hex(group, ID_1met2_1, POINT_CONVERSION_UNCOMPRESSED, ctx);
        string id_1met2_1_str = GetBinaryStringFromHexString(id_1met2_1[i]);

        //id�еĹ�ϣ����
        EC_POINT* ID_h = NULL;
        ID_h = EC_POINT_new(group);
        EC_POINT_mul(group, ID_h, NULL, pub_key, ri[i], ctx);

        const unsigned char* id_h = (const unsigned char*)(EC_POINT_point2hex(group, ID_h, POINT_CONVERSION_COMPRESSED, ctx));

        unsigned char hash_idh[20] = { 0 };
        SHA1(id_h, strlen((char*)id_h), hash_idh);

        
        //hash�ַ�����ת�ɴ���
        BIGNUM* idh = BN_new();
        BN_bin2bn(hash_idh, 20, idh);

        //��hash�Ĵ�����ʽת�ɶ�����
        string bf = GetBinaryStringFromHexString(BN_bn2hex(idh));

        int* intbf = new int[bf.length()];
        for (int i = 0; i < bf.length(); i++) {
            intbf[i] = bf[i] - '0';
        }

        

        //RID��hash�����
        int* id_2 = new int[af.length()];
        for (int k = 0; k < af.length(); k++) {
            id_2[k] = intbf[k] ^ intaf[k];
        }

        //AIDM��ʱ��ʼ
        QueryPerformanceFrequency(&AIDM_tc);
        QueryPerformanceCounter(&AIDM_s);

        //id_2��string��ʽ 
        for (int j = 0; j < af.length(); j++) {
            id_2_str[i] = id_2_str[i] + to_string(id_2[j]);            ///��ʱ0.6ms      �ṹ����ʡȥ
        }

        //AIDM��ʱ����
        QueryPerformanceCounter(&AIDM_e);
        double time_1 = (double)(AIDM_e.QuadPart - AIDM_s.QuadPart) / (double)AIDM_tc.QuadPart * 1000;


        ID_1met2[i] = id_1met2_1_str + id_2_str[i];

        
        //�û�1��׼������Ϣǩ�����˴���Ϣʡ��RSSI

        //���㰢����
        char* ID_1met2_char = new char[ID_1met2[i].length()];
        strcpy(ID_1met2_char, ID_1met2[i].c_str());
        
        unsigned char hash_ID_1met2[20] = { 0 };
        SHA1((const unsigned char*)ID_1met2_char, strlen(ID_1met2_char), hash_ID_1met2);

        BIGNUM* alpha = BN_new();
        BN_bin2bn(hash_ID_1met2, 20, alpha);


        //���㱴��
        string ID_1met2_T = ID_1met2[i] + T[i];
       
        char* ID_1met2_T_char = new char[ID_1met2_T.length()];
        strcpy(ID_1met2_T_char, ID_1met2_T.c_str());
        // cout << "ID_1met2_T_char:" << ID_1met2_T_char << endl;
        // cout << endl;

        unsigned char hash_ID_1met2_T[20] = { 0 };
        SHA1((const unsigned char*)ID_1met2_T_char, strlen(ID_1met2_T_char), hash_ID_1met2_T);

        BIGNUM* beta = BN_new();
        BN_bin2bn(hash_ID_1met2_T, 20, beta);


        


        //��ʼ��ʽ����ǩ��

        BIGNUM* way = BN_new();
        sign[i] = BN_new();
        BN_mul(way, w[i], beta, ctx);
        BN_add(sign[i], way, ri[i]);
        BN_mul(way, kd, alpha, ctx);
        BN_mod_add(sign[i], sign[i], way, EC_GROUP_get0_order(group), ctx);

       
        ttt = ttt + time_1;

        BN_free(way);
        BN_free(beta);
        BN_free(alpha);
        BN_free(idh);
        EC_POINT_free(ID_h);
        BN_free(rid);
        EC_POINT_free(ID_1met2_1);
      
    }

    cout << "�����������ɺ�ǩ�� time = " << ttt/user_sum << "ms" << endl;
    

    ofstream outfile;
    for (int i = 0; i < user_sum; i++) {
        outfile.open("C:\\Users\\87973\\source\\repos\\Project1\\User_data\\user_2_EH\\ID_" + to_string(user_nums[i]) + "met_2.txt", ios::out);//������������txt
    //ios::out	������ļ��������������������ļ������ڣ��򴴽�һ���������ƵĿ��ļ�
        outfile << ID_1met2[i];            //����ID
        outfile << ends;
        outfile << endl;

        outfile << id_1met2_1[i];              //ID_1
        outfile << ends;
        outfile << endl;

        outfile << id_2_str[i];                  //ID_2
        outfile << ends;
        outfile << endl;

        outfile << T[i];                  //T
        outfile << ends;
        outfile << endl;

        outfile << BN_bn2hex(sign[i]);                  //sign
        outfile << ends;
        outfile << endl;

        outfile.close();
    }


    EC_GROUP_free(group), group = NULL;
    

    BN_CTX_free(ctx);
    BN_free(p);//BIGNUM* p, * a, * b, * gx, * gy, * z;* pri_key,sk[n],sigma_g,* x[n],*rm,*y[n],* u, * xxxx[n]
    BN_free(a);
    BN_free(b);
    BN_free(gx);
    BN_free(gy);
    BN_free(z);

    BN_free(kd);
    for (int i = 0; i < user_sum; i++) {
        BN_free(ri[i]);
        BN_free(w[i]);
        BN_free(z);
        BN_free(sign[i]);
    }

    return 0;


}
