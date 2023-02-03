#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>


unsigned char* hashPassword(char* password, unsigned char* digest);
int checkPasswordLength(char *password);


int main(int argc, const char * argv[]){
    
    char password[128];
    unsigned char digest[EVP_MAX_MD_SIZE];     

    if (argc == 1){
        printf("Enter the password: ");
        scanf("%s", password);
    } else {
        strcpy(password, argv[1]);
    }

    checkPasswordLength(password);

    unsigned char* hash = hashPassword(password, digest);     

    return 0; 
}


// Функция для получения длины пароля
int checkPasswordLength(char *password){

    if(strlen(password) > 128){
        fprintf(stderr, "Error: The password length exceeds 128 characters\n");
        exit(1);
    }

    return 0;
}

// Функция для хэширования строки с паролем с использованием SHA256
unsigned char* hashPassword(char* password, unsigned char* digest) {

    EVP_MD_CTX *mdctx;
    int digestlen;  

    if((mdctx = EVP_MD_CTX_create()) == NULL) {
        fprintf(stderr, "Error!\n");   
        return 0;   
    }

    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {  
        fprintf(stderr, "Error!\n");   
        return 0;   
    }

    if(1 != EVP_DigestUpdate(mdctx, password, strlen(password))) {  
        fprintf(stderr, "Error!\n");   
        return 0;  
    }


    if(1 != EVP_DigestFinal_ex(mdctx, digest, &digestlen)) {    
        fprintf(stderr, "Error!\n");     
        return 0;  
    }

    for (int i = 0; i < digestlen; i++){      
        printf("%02x", digest[i]);      }

    printf("\n");

    EVP_MD_CTX_destroy(mdctx);        

    //возврат указателя на укороченный SHA-256-дайджест
    return digest;                  
}
