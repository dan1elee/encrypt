#include "receiver.h"
#define SHA_BUFFER_SIZE 32
int sendSeed(unsigned char *seed,int s_len,int sock){
    char* data=(char*)seed;
    int len=s_len;
    int rc;
     do{
        rc=write(sock, data, len);
        if(rc<0){
            printf("errno while sending seed is %d\n",errno);
            exit(0);
        }else{
            data+=rc;
            len-=rc;
        }
    }while(len>0);
    return len;
}

int recvEncryptedData(unsigned char *dae,int d_len,int sock){
    int rc;
    int len=d_len;
    do{
        rc=read(sock, dae, len);
        if(rc<0){
            printf("errno while receiving encrypted data is %d\n",errno);
            exit(0);
        }else{
            dae+=rc;
            len-=rc;
        }
    }while(len>0);
    return 0;

}

int recvPKeyAndLen(unsigned char *b_f, int32_t *pk_len,int sock){
    int left1=sizeof(*pk_len);
    int left2=0;
    char *data=(char*)pk_len;
    int rc1;
    int rc2;
    do{
        rc1=read(sock, data, left1);
        if(rc1<0){
            printf("errno while receiving public key length is %d\n",errno);
            exit(0);
        }else{
            data+=rc1;
            left1-=rc1;
        }
    }while(left1>0);


    left2=ntohl(*pk_len);
    do{
        rc2=read(sock, b_f, left2);
        if(rc2<0){
            printf("errno while receiving public key is %d\n",errno);
            exit(0);
        }else{
            b_f+=rc2;
            left2-=rc2;
        }
    }while(left2>0);
    return 0;
}

int genSeed(unsigned char* ranstr){
    int i,flag;
    srand(time(NULL));
    for(i = 0; i < SEED_LEN-1; i ++)
    {
		flag = rand()%3;
		switch(flag)
		{
		case 0:
			*(ranstr+i) = rand()%26 + 'a';
			break;
		case 1:
			*(ranstr+i) = rand()%26 + 'A';
			break;
		case 2:
			*(ranstr+i) = rand()%10 + '0';
			break;
		}
    }
    return i;
}

int recvFile(unsigned char *data_after_encrypt,unsigned char *data_after_decrypt,AES_KEY *AESDecryptKey,int sock){
    unsigned long fsize=0;
    char fs[8];
    char p_fs[16];
    char d_fs[16];
    recvEncryptedData((unsigned char*)p_fs,sizeof(p_fs),sock);
    AES_decrypt((unsigned char*)p_fs, (unsigned char*)d_fs, AESDecryptKey);
    strncpy(fs,(const char*)d_fs,8);
    fsize=*((unsigned long*)fs);
    printf("File size:%lu\n",fsize);
    unsigned long times=((unsigned long)(fsize/16))+1;
    char fn[256];
    memset(fn,0,sizeof(fn));
    char e_fn[256];
    memset(e_fn,0,sizeof(e_fn));
    recvEncryptedData((unsigned char*)e_fn,sizeof(e_fn),sock);
    AES_decrypt((unsigned char*)e_fn, (unsigned char*)fn, AESDecryptKey);
    printf("File name:%s\n",fn);
    FILE *fp;
    if((fp=fopen((const char*)fn,"wb"))==NULL){
        printf("File error!\nEnding the program!\n");
        exit(0);
    }
    printf("Writing file...\n");
    for(int i=0;i<times;i++){
        recvEncryptedData(data_after_encrypt,16,sock);
        AES_decrypt(data_after_encrypt, data_after_decrypt, AESDecryptKey);
        if(i!=times-1){
            fwrite(data_after_decrypt,16,1,fp);
        }else{
            fwrite(data_after_decrypt,fsize%16,1,fp);
        }
    }
    fclose(fp);
    unsigned char recvHash_encrypt[16];
    unsigned char recvHash[SHA256_DIGEST_LENGTH];
    recvEncryptedData(recvHash_encrypt, 16, sock);
    AES_decrypt(recvHash_encrypt,recvHash, AESDecryptKey);

    recvEncryptedData(recvHash_encrypt, 16, sock);
    AES_decrypt(recvHash_encrypt,recvHash+16, AESDecryptKey);

    fp=fopen((const char*)fn, "rb");
    unsigned char hash[SHA256_DIGEST_LENGTH];
    fileSHA256(fp,fsize,hash);
    int cmpResult = memcmp(recvHash, hash, SHA256_DIGEST_LENGTH);
    if (cmpResult == 0){
        printf("SHA-256 match\n");
    } else {
        printf("SHA-256 not match\n");
    }
    printf("Completes!\n");
}

int fileSHA256(FILE* fp, unsigned long fsize, unsigned char* hash){
    fseek(fp, 0, SEEK_SET);
    unsigned char buffer[SHA_BUFFER_SIZE];
    size_t bytes_read;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned long times=((unsigned long)(fsize/sizeof(buffer)))+1;
    for(unsigned long i=0;i<times;i++){
        bytes_read = fread(buffer, sizeof(char), sizeof(buffer), fp);
        SHA256_Update(&sha256, buffer, bytes_read);
    }
    SHA256_Final(hash, &sha256);
    return 0;
}