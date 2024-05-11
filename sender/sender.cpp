#include <stdlib.h>
#include <time.h>
#include "sender.h"
#define SHA_BUFFER_SIZE 32
int getServerSocket(const char *ip,int port){
    int serv_sock=socket(AF_INET,SOCK_STREAM,0);
    if(serv_sock!=-1){
        int opt = 1;
        setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));//for checking
        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;  //ipv4
        serv_addr.sin_addr.s_addr = inet_addr(ip);  //ip address
        serv_addr.sin_port = htons(port);  //port
        if(bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))!=-1){
            listen(serv_sock,20);
            return serv_sock;
        }else{
            printf("errno for bind() in getServerSocket is %d\n",errno);
            printf("ending the program!\n");
            exit(0);
        }
    }else{
        printf("errno for socket() in getServerSocket is %d\n",errno);
        printf("ending the program!\n");
        exit(0);
    }
    return -1;
}

int waitForConnection(int serv_sock){
    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size = sizeof(clnt_addr);
    int clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
    if(clnt_sock!=-1){
        return clnt_sock;
    }else{
        printf("errno for waitForConnection is %d\n",errno);
        printf("ending the program!\n");
        exit(0);
    }
    return -1;
}

int sendKey(unsigned char *pk,int pk_len,int clnt_sock){
    //transfer integer
    int32_t conv=htonl(pk_len);
    char *data = (char*)&conv;
    int len = sizeof(conv);
    char *key=(char*)pk;
    //rc1 and rc2 stands for how much data sent this round
    int rc1;
    do{
        rc1=write(clnt_sock, data, len);
        if(rc1<0){
            printf("errno while sending public key length is %d\n",errno);
            exit(0);
        }else{
            data+=rc1;
            len-=rc1;
        }
    }while(len>0);

    int rc2;
    do{
        rc2=write(clnt_sock, key, pk_len);
        if(rc2<0){
            printf("errno while sending public key is %d\n",errno);
            exit(0);
        }else{
            key+=rc2;
            pk_len-=rc2;
        }
    }while(pk_len>0);
    return 0;
}

int sendData(unsigned char *data,int d_len,int clnt_sock){
    int rc;
    int len=d_len;
    do{
        rc=write(clnt_sock, data, len);
        if(rc<0){
            printf("errno while sending encrypted data is %d\n",errno);
            exit(0);
        }else{
            data+=rc;
            len-=rc;
        }

    }while(len>0);
    return len;
}

int recvSeed(unsigned char *s_b,int s_len,int clnt_sock){
    int rc;
    int len=s_len;
    do{
        rc=read(clnt_sock, s_b, len);
        if(rc<0){
            printf("errno while receive seed is %d\n",errno);
            exit(0);
        }else{
            s_b+=rc;
            len-=rc;
        }
    }while(len>0);
    return len;
}


int sendFile(FILE* fp,unsigned long fsize,unsigned char *path,unsigned char *data_to_encrypt,unsigned char *data_after_encrypt,AES_KEY *AESEncryptKey,int clnt_sock){
    //send file size
    unsigned long times=((unsigned long)(fsize/16))+1;
    printf("File size:%lu bytes\n",fsize);
    char* fs=(char*)&fsize;
    char p_fs[16];//padding to 16bytes
    memset(p_fs,0,sizeof(p_fs));
    strncpy(p_fs,(const char*)fs,sizeof(fs));
    char e_fs[16];
    AES_encrypt((unsigned char*)p_fs, (unsigned char*)e_fs, AESEncryptKey);
    sendData((unsigned char*)e_fs,sizeof(e_fs),clnt_sock);
    //send file name
    const char ch='/';
    const char *ret;
    ret=strrchr((const char*)path,ch);
    char fn[256];
    memset(fn,0,sizeof(fn));
    if(ret!=NULL){
        strcpy(fn,(const char*)ret+1);
    }else{
        strcpy(fn,(const char*)path);
    }
    printf("File name:%s\n",fn);
    char e_fn[256];
    AES_encrypt((unsigned char*)fn, (unsigned char*)e_fn, AESEncryptKey);
    sendData((unsigned char*)e_fn,sizeof(e_fn),clnt_sock);
    //send data
    printf("Sending File...\n");
    for(unsigned long i=0;i<times;i++){
        fread(data_to_encrypt,16,1,fp);
        AES_encrypt(data_to_encrypt, data_after_encrypt, AESEncryptKey);
        sendData(data_after_encrypt,16,clnt_sock);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    fileSHA256(fp, fsize, hash);

    unsigned char hash16[16];
    unsigned char hash16_encrypt[16];
    memcpy(hash16,hash,16);
    AES_encrypt(hash16,hash16_encrypt,AESEncryptKey);
    sendData(hash16_encrypt, 16, clnt_sock);

    memcpy(hash16,hash+16,16);
    AES_encrypt(hash16,hash16_encrypt,AESEncryptKey);
    sendData(hash16_encrypt, 16, clnt_sock);

    printf("Completes!\n");
    return 0;
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
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    return 0;
}

int sendFileWithRandomError(FILE* fp,unsigned long fsize,unsigned char *path,unsigned char *data_to_encrypt,unsigned char *data_after_encrypt,AES_KEY *AESEncryptKey,int clnt_sock){
    //send file size
    unsigned long times=((unsigned long)(fsize/16))+1;
    printf("File size:%lu bytes\n",fsize);
    char* fs=(char*)&fsize;
    char p_fs[16];//padding to 16bytes
    memset(p_fs,0,sizeof(p_fs));
    strncpy(p_fs,(const char*)fs,sizeof(fs));
    char e_fs[16];
    AES_encrypt((unsigned char*)p_fs, (unsigned char*)e_fs, AESEncryptKey);
    sendData((unsigned char*)e_fs,sizeof(e_fs),clnt_sock);
    //send file name
    const char ch='/';
    const char *ret;
    ret=strrchr((const char*)path,ch);
    char fn[256];
    memset(fn,0,sizeof(fn));
    if(ret!=NULL){
        strcpy(fn,(const char*)ret+1);
    }else{
        strcpy(fn,(const char*)path);
    }
    printf("File name:%s\n",fn);
    char e_fn[256];
    AES_encrypt((unsigned char*)fn, (unsigned char*)e_fn, AESEncryptKey);
    sendData((unsigned char*)e_fn,sizeof(e_fn),clnt_sock);
    //send data
    printf("Sending File...\n");
    srand((unsigned)time(NULL));
    
    bool flag = false;
    for(unsigned long i=0;i<times;i++){
        fread(data_to_encrypt,16,1,fp);
        double r = rand() / double(RAND_MAX);
        if (r < 0.01) {
            flag = true;
            int bit = (int)(128 * rand() / double(RAND_MAX));
            data_to_encrypt[bit>>3] = data_to_encrypt[bit>>3] ^ (1<<(bit % 8));
        }
        AES_encrypt(data_to_encrypt, data_after_encrypt, AESEncryptKey);
        sendData(data_after_encrypt,16,clnt_sock);
    }
    if(flag){
        printf("bits changed in this file.\n");
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    fileSHA256(fp, fsize, hash);

    unsigned char hash16[16];
    unsigned char hash16_encrypt[16];
    memcpy(hash16,hash,16);
    AES_encrypt(hash16,hash16_encrypt,AESEncryptKey);
    sendData(hash16_encrypt, 16, clnt_sock);

    memcpy(hash16,hash+16,16);
    AES_encrypt(hash16,hash16_encrypt,AESEncryptKey);
    sendData(hash16_encrypt, 16, clnt_sock);

    printf("Completes!\n");
    return 0;
}