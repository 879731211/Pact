#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>


//公钥验证签名
int my_verify(const char* input, int input_len, ECDSA_SIG* signret, const char* pub_key_fn)
{
    EC_KEY* p_dsa = NULL;
    FILE* file = NULL;
    int ret = 0;

    if ((file = fopen(pub_key_fn, "rb")) == NULL)
    {
        ret = -1;
        return ret;
    }

    if ((p_dsa = PEM_read_EC_PUBKEY(file, NULL, NULL, NULL)) == NULL)
    {
        ret = -2;
        fclose(file);
        return ret;
    }

    fclose(file);

    ret = ECDSA_do_verify(input, input_len, signret, p_dsa);
    if (ret != 1)
    {
        ret = -3;
        printf("ECDSA_verify err!\n");
        EC_KEY_free(p_dsa);
        return ret;
    }

    printf("verify is ok!\n");

    EC_KEY_free(p_dsa);

    return 0;
}


//私钥签名
int my_sign(const char* input, int input_len, const char* pri_key_fn)
{
    EC_KEY* p_dsa = NULL;
    ECDSA_SIG* s;
    FILE* file = NULL;
    unsigned char* data[2];
    int nid;
    int signlen = 0;
    int i = 0;
    int ret = 0;

    memset(data, 0x00, sizeof(data));

    nid = 0;

    file = fopen(pri_key_fn, "rb");
    if (!file)
    {
        ret = -1;
        return ret;
    }

    if ((p_dsa = PEM_read_ECPrivateKey(file, NULL, NULL, NULL)) == NULL)
    {
        ret = -2;
        fclose(file);
        return ret;
    }

    fclose(file);

    s = ECDSA_do_sign(input, input_len, p_dsa);
    if (s == NULL)
    {
        ret = -3;
        EC_KEY_free(p_dsa);
        return ret;
    }

    data[0] = BN_bn2hex(s->r); //二进制转十六进制
    data[1] = BN_bn2hex(s->s);

    EC_KEY_free(p_dsa);
    ECDSA_SIG_free(s);

    printf("%s\n", data[0]);
    printf("%s\n", data[1]);

    free(data[0]);
    free(data[1]);

    return 0;
}

int main(int argc, char** argv)
{
    char src[512 + 1];
    char dst_str[2][512 + 1];
    int src_len;
    int ret;
    FILE* f;

    memset(src, 0x00, sizeof(src));
    //memset(dst, 0x00, sizeof(dst));

    if (argv[1][0] == 's')
    {
        strcpy(src, "aedewderdfercfrtvgfrtfgrtgfrtgvtrgtrvgtyebtybytbnybyuyubndrybrfgswdhyewhde");
        src_len = strlen(src);

        ret = my_sign(src, src_len, argv[2]);
        if (ret)
        {
            fprintf(stderr, "Error\n");
        }
    }
    else
    {
        ECDSA_SIG* s = (ECDSA_SIG*)malloc(sizeof(ECDSA_SIG));

        strcpy(src, "aedewderdfercfrtvgfrtfgrtgfrtgvtrgtrvgtyebtybytbnybyuyubndrybrfgswdhyewhde");
        strncpy(dst_str[0], argv[2], 512);
        strncpy(dst_str[1], argv[3], 512);
        src_len = strlen(src);

        s->r = BN_new();
        s->s = BN_new();

        BN_hex2bn(&(s->r), dst_str[0]); //十六进制转二进制
        BN_hex2bn(&(s->s), dst_str[1]);

        ret = my_verify(src, src_len, s, argv[1]);
        if (ret)
        {
            fprintf(stderr, "Error\n");
        }

        BN_free(s->r);
        BN_free(s->s);

        free(s);
    }

    return 0;
}