#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define BUFLEN             1024 

/* BIO filters */
#define BIO_F_BASE64       BIO_f_base64()
#define BIO_F_BUFFER       BIO_f_buffer()
#define BIO_F_CIPHER       BIO_f_cipher()
#define BIO_F_MD       	   BIO_f_md()
#define BIO_F_NULL         BIO_f_null()

/* Source/Sink Bios */
#define BIO_S_MEM          BIO_s_mem()
#define BIO_S_ACCEPT       BIO_s_accept()
#define BIO_S_BIO          BIO_s_bio()
#define BIO_S_CONNECT      BIO_s_connect()
#define BIO_S_FD           BIO_s_fd()
#define BIO_S_FILE         BIO_s_file()
#define BIO_S_NULL         BIO_s_null()
#define BIO_S_SOCKET       BIO_s_socket()

#define BIO_FLAGS_NO_SINK  0x99

#define EVP_NULL			0

#define EVP_DES_CBC			1	
#define EVP_DES_ECB			2	
#define EVP_DES_CFB			3	
#define EVP_DES_OFB			4	

#define EVP_DES_EDE_CBC    	5 
#define EVP_DES_EDE        	6 
#define EVP_DES_EDE_CFB     7 
#define EVP_DES_EDE_OFB     8 

#define EVP_DES_EDE3_CBC    9
#define EVP_DES_EDE3        10 
#define EVP_DES_EDE3_CFB    11 
#define EVP_DES_EDE3_OFB    12 

#define EVP_DESX_CBC        13 

#define EVP_RC4             20 

#define EVP_IDEA_CBC        30 
#define EVP_IDEA_ECB        31 
#define EVP_IDEA_CFB        32 
#define EVP_IDEA_OFB        33 

#define EVP_RC2_CBC         40
#define EVP_RC2_ECB         41
#define EVP_RC2_CFB         42 
#define EVP_RC2_OFB         43 

#define EVP_BF_CBC          50 
#define EVP_BF_ECB          51 
#define EVP_BF_CFB          52 
#define EVP_BF_OFB          53 

#define EVP_CAST5_CBC       60 
#define EVP_CAST5_ECB       61 
#define EVP_CAST5_CFB       62 
#define EVP_CAST5_OFB       63 

#define EVP_RC5_32_12_16_CBC 70 
#define EVP_RC5_32_12_16_ECB 71 
#define EVP_RC5_32_12_16_CFB 72 
#define EVP_RC5_32_12_16_OFB 73 

#define EVP_MD2		1000
#define EVP_MD5		1001
#define EVP_MDC2	1002
#define EVP_SHA		1003
#define EVP_SHA1	1004

#define PACKAGE_NAME    	"Crypt::OpenSSL::BIO"

#define noAlloc()			croak("Cannot allocate memory to " PACKAGE_NAME)

