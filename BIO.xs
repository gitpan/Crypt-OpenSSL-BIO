#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "BIO.h"

static int nid = 1;
static int bid = 0;

typedef struct encstr {
	void * cipher;
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char iv[EVP_MAX_IV_LENGTH];
} encstr;

typedef struct biostr {
    BIO * bio;
	struct biostr * next;
    int buflen;
    int freed;
	int id;
	struct encstr * enc;
} biostr;

typedef biostr * Crypt_OpenSSL_BIO;


Crypt_OpenSSL_BIO
init_BIO(int type, int buflen)
{
	Crypt_OpenSSL_BIO bio;

	if (New(nid++, (void*)bio, sizeof(biostr), Crypt_OpenSSL_BIO) == NULL)
		noAlloc();

	bio->next = NULL;
	bio->buflen = (buflen ? buflen : BUFLEN);
	bio->freed = 0;
	bio->id = bid++;

    if (New(nid++, (void*)bio->enc, sizeof(encstr), encstr *) == NULL)
        noAlloc();

	bio->enc->cipher = EVP_enc_null();
	memset(bio->enc->key, 0, sizeof(unsigned char));
    memset(bio->enc->iv, 0, sizeof(unsigned char));

	switch (type){
		case BIO_TYPE_NONE:			bio->bio = BIO_new(BIO_S_NULL); break;
		case BIO_TYPE_MEM:			bio->bio = BIO_new(BIO_S_MEM); break;
		case BIO_TYPE_FILE:			bio->bio = BIO_new(BIO_S_FILE); break;
		case BIO_TYPE_FD:			bio->bio = BIO_new(BIO_S_FD); break;
		case BIO_TYPE_SOCKET:		bio->bio = BIO_new(BIO_S_SOCKET); break;
		case BIO_TYPE_NULL:			bio->bio = BIO_new(BIO_S_NULL); break;
		case BIO_TYPE_MD:			bio->bio = BIO_new(BIO_F_MD); break;
		case BIO_TYPE_BUFFER:		bio->bio = BIO_new(BIO_F_BUFFER); break;
		case BIO_TYPE_CIPHER:		bio->bio = BIO_new(BIO_F_CIPHER); break;
		case BIO_TYPE_BASE64:		bio->bio = BIO_new(BIO_F_BASE64); break;
		case BIO_TYPE_CONNECT:		bio->bio = BIO_new(BIO_S_CONNECT); break;
		case BIO_TYPE_ACCEPT:		bio->bio = BIO_new(BIO_S_ACCEPT); break;
		case BIO_TYPE_NULL_FILTER:	bio->bio = BIO_new(BIO_F_NULL); break;
		case BIO_TYPE_BIO:			bio->bio = BIO_new(BIO_S_BIO); break;
		default:  					bio->bio = BIO_new(BIO_S_NULL); break;
	}

	return bio; 
}


int
set_BIO(Crypt_OpenSSL_BIO bio, int type)
{
    int ret;

    switch (type){
        case BIO_TYPE_NONE:         ret = BIO_set(bio->bio, BIO_S_NULL); break;
        case BIO_TYPE_MEM:          ret = BIO_set(bio->bio, BIO_S_MEM); break;
        case BIO_TYPE_FILE:         ret = BIO_set(bio->bio, BIO_S_FILE); break;
        case BIO_TYPE_FD:           ret = BIO_set(bio->bio, BIO_S_FD); break;
        case BIO_TYPE_SOCKET:       ret = BIO_set(bio->bio, BIO_S_SOCKET); break;
        case BIO_TYPE_NULL:         ret = BIO_set(bio->bio, BIO_S_NULL); break;
        case BIO_TYPE_MD:           ret = BIO_set(bio->bio, BIO_F_MD); break;
        case BIO_TYPE_BUFFER:       ret = BIO_set(bio->bio, BIO_F_BUFFER); break;
        case BIO_TYPE_CIPHER:       ret = BIO_set(bio->bio, BIO_F_CIPHER); break;
        case BIO_TYPE_BASE64:       ret = BIO_set(bio->bio, BIO_F_BASE64); break;
        case BIO_TYPE_CONNECT:      ret = BIO_set(bio->bio, BIO_S_CONNECT); break;
        case BIO_TYPE_ACCEPT:       ret = BIO_set(bio->bio, BIO_S_ACCEPT); break;
        case BIO_TYPE_NULL_FILTER:  ret = BIO_set(bio->bio, BIO_F_NULL); break;
        case BIO_TYPE_BIO:          ret = BIO_set(bio->bio, BIO_S_BIO); break;
        default:                    ret = BIO_set(bio->bio, BIO_S_NULL); break;
    }

    return ret;
}


int 
look_for_sink(Crypt_OpenSSL_BIO bio)
{
	int ret = 0;
	Crypt_OpenSSL_BIO btmp = bio;

	do {
		if (btmp->bio->method->type & BIO_TYPE_SOURCE_SINK)
		{
			ret = 1;
			break;
		}

		btmp = btmp->next;
		if (btmp == NULL) break;
	} while (btmp);

	return ret;
}


SV *
read_data(Crypt_OpenSSL_BIO bio, char *type)
{
    char *data;
	SV *result;
	int i = 0;
	int total = 0;
	STRLEN len;

    if (New(0, data, bio->buflen+1, char) == NULL)
        noAlloc();

	memset(data, 0, bio->buflen+1);
	result = sv_2mortal(NEWSV(0, bio->buflen));
	SvPOK_on(result);

	if (type == "read")
	{
		while ( (i = BIO_read(bio->bio, data, bio->buflen)) > 0){
			total += i;
			len = SvCUR(result);

			if ((len > 0) && (total > len))
			{
				SvGROW(result, total - len);
			}

			sv_catpv(result, data);
			memset(data, 0, bio->buflen+1);
		}
	}
	else
	{
        while ( (i = BIO_gets(bio->bio, data, bio->buflen)) > 0){
            total += i;
            len = SvCUR(result);

            if ((len > 0) && (total > len))
            {
                SvGROW(result, total - len);
            }

            sv_catpv(result, data);
            memset(data, 0, bio->buflen+1);
        }
	}

	Safefree(data);
	return result;
}


int
write_data(Crypt_OpenSSL_BIO bio, char* data, char *type)
{
    // Filter BIOs require a source/sink in order to
    // read/write. If none is present return flag

    if (look_for_sink(bio) == 0)
        return BIO_FLAGS_NO_SINK;

	if (type == "write")
 		return BIO_write(bio->bio, data, strlen(data));
	else
		return BIO_puts(bio->bio, data);
}


MODULE = Crypt::OpenSSL::BIO	PACKAGE = Crypt::OpenSSL::BIO	PREFIX = Crypt_BIO_
PROTOTYPES: DISABLE


void
Crypt_BIO_new(CLASS, type, buflen = BUFLEN)
	char *CLASS
	int type
	int buflen
PPCODE:
{
	Crypt_OpenSSL_BIO bio;
    bio = init_BIO(type, buflen); 

    XPUSHs(sv_setref_pv(sv_newmortal(),
                   PACKAGE_NAME, (void *)bio));
	XSRETURN(1);
}


void
Crypt_BIO_DESTROY(self)
    Crypt_OpenSSL_BIO self
PPCODE:
{
	if (!self->freed)
    	BIO_vfree(self->bio);

	Safefree(self);
	XSRETURN_YES;
}


##################################################
# Sets the amount of memory to consume on calls 
# to New(). Default value is BUFLEN.
#
# This is not part of the openssl specification.
##################################################

void
Crypt_BIO_buflen(self, buflen = 0)
	Crypt_OpenSSL_BIO self;
	int buflen;
PPCODE:
{
	if (buflen > 0)
	{
		self->buflen = buflen;
		XSRETURN_YES;
	}	
	else
	{
		XSRETURN_IV(self->buflen);
	}
}


##################################################
# This gets the next Crypt::OpenSSL::BIO object 
# in a given chain. This is not working quite 
# right yet as inline calls kill the current object 
# within the Perl code. Ex:
#
# $bio->next->read();
#
# This will DESTROY $bio. If you do an assignment 
# first as in:
#
# my $n = $bio->next();
# $n->read();
#
# then there is no problem as far as I can tell.
##################################################

void
Crypt_BIO_next(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
    XPUSHs(sv_setref_pv(sv_newmortal(),
                   PACKAGE_NAME, (Crypt_OpenSSL_BIO)self->next));
	XSRETURN(1);
}


##################################################
# Appends bio to self's chain. This is suppose to 
# return a BIO *, but I didn't see the point 
# within this context.
##################################################

void
Crypt_BIO_push(self, bio)
	Crypt_OpenSSL_BIO self;
	Crypt_OpenSSL_BIO bio;
PPCODE:
{
	self->next = bio;
	self->bio = BIO_push(self->bio, bio->bio);
	XSRETURN_YES;
}


##################################################
# Removes self from whatever chain it is attached 
# to. This is suppose to return the next BIO in 
# the chain, but due to problems with the next() 
# function above, I am refraining from creating 
# more. 
##################################################

void 
Crypt_BIO_pop(self)
	Crypt_OpenSSL_BIO self;
PPCODE:
{
	BIO_pop(self->bio);
	XSRETURN_YES;
}


##################################################
# Read/Write functions
##################################################

void 
Crypt_BIO_read(self)
	Crypt_OpenSSL_BIO self;
PPCODE:
{
	XPUSHs(read_data(self, "read"));
	XSRETURN(1);
}


void
Crypt_BIO_gets(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
    XPUSHs(read_data(self, "gets"));
    XSRETURN(1);
}


void 
Crypt_BIO_write(self, data)
	Crypt_OpenSSL_BIO self;
	char *data;
PPCODE:
{
	XSRETURN_IV(write_data(self, data, "write"));
}


void
Crypt_BIO_puts(self, data)
    Crypt_OpenSSL_BIO self;
    char *data;
PPCODE:
{
    XSRETURN_IV(write_data(self, data, "puts"));
}


##################################################
# Flushes internal data and signals EOF to the BIO
##################################################

void 
Crypt_BIO_flush(self)
	Crypt_OpenSSL_BIO self;
PPCODE:
{
	XSRETURN_IV(BIO_flush(self->bio));
}


##################################################
# The various functions to free a BIO. These are 
# not really necessary to call since the destructor 
# can take care of it. These are mostly provided 
# for completeness.
##################################################

void 
Crypt_BIO_free(self)
	Crypt_OpenSSL_BIO self;
PPCODE:
{
	self->freed = 1;
	XSRETURN_IV(BIO_free(self->bio));
}


void 
Crypt_BIO_vfree(self)
	Crypt_OpenSSL_BIO self;
PPCODE:
{
	self->freed = 1;
	BIO_vfree(self->bio);
	XSRETURN_YES;
}


void
Crypt_BIO_free_all(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
	Crypt_OpenSSL_BIO btmp = self; 

	do {
		if (btmp == NULL) break;
		btmp->freed = BIO_free(btmp->bio);
		btmp = btmp->next;
	} while (btmp);

	XSRETURN_YES;
}


##################################################
# Sets the method of an already existing BIO
##################################################

void
Crypt_BIO_set(self, type)
    Crypt_OpenSSL_BIO self;
    int type;
PPCODE:
{
	XSRETURN_IV(set_BIO(self, type));
}


##################################################
# This returns an integer representing the type 
# of BIO. The actual openssl function is called 
# BIO_method_type().
##################################################

void 
Crypt_BIO_type(self)
	Crypt_OpenSSL_BIO self;
PPCODE:
{
	XSRETURN_IV(self->bio->method->type);
}


##################################################
# Resets the internal state of the BIO. This has 
# different effects depending on the BIO type.
##################################################

void
Crypt_BIO_reset(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
	XSRETURN_IV(BIO_reset(self->bio));
}


##################################################
# Returns 1 if the BIO has read EOF.
##################################################

void
Crypt_BIO_eof(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
	XSRETURN_IV(BIO_eof(self->bio));
}


##################################################
# Resets a file BIO's file position pointer to 
# offset bytes from start of file.
##################################################

void
Crypt_BIO_seek(self, offset)
    Crypt_OpenSSL_BIO self;
    int offset;
PPCODE:
{
	if (self->bio->method->type != BIO_TYPE_FILE &&  
        self->bio->method->type != BIO_TYPE_FD)
			XSRETURN_NO;

	XSRETURN_IV(BIO_seek(self->bio, offset));
}


##################################################
# Returns current file position of a file related 
# BIO.
##################################################

void
Crypt_BIO_tell(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
    if (self->bio->method->type != BIO_TYPE_FILE &&
        self->bio->method->type != BIO_TYPE_FD)
            XSRETURN_NO;

	XSRETURN_IV(BIO_tell(self->bio));
}


##################################################
# This handles BIO_set_close() and BIO_get_close() 
##################################################

void
Crypt_BIO_close(self, flag = -1)
    Crypt_OpenSSL_BIO self;
    int flag;
PPCODE:
{
	if (flag == -1)
		XSRETURN_IV(BIO_get_close(self->bio));
	else
		XSRETURN_IV(BIO_set_close(self->bio, (long)flag));
}


##################################################
# Returns the number of characters in the BIOs
# read buffer.
##################################################

void
Crypt_BIO_read_pending(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
	XSRETURN_IV(BIO_ctrl_pending(self->bio));
}


##################################################
# Returns the number of characters in the BIOs
# write buffer.
##################################################

void
Crypt_BIO_write_pending(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
	XSRETURN_IV(BIO_ctrl_wpending(self->bio));
}


##################################################
# These functions determine why a BIO was not 
# able to read/write data.
##################################################

void
Crypt_BIO_should_retry(self)
	Crypt_OpenSSL_BIO self;
PPCODE:
{
	XSRETURN_IV(BIO_should_retry(self->bio));
}


void
Crypt_BIO_should_write(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
    XSRETURN_IV(BIO_should_write(self->bio));
}


void
Crypt_BIO_should_read(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
    XSRETURN_IV(BIO_should_read(self->bio));
}


void
Crypt_BIO_should_io_special(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
    XSRETURN_IV(BIO_should_io_special(self->bio));
}


void
Crypt_BIO_retry_type(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
    XSRETURN_IV(BIO_retry_type(self->bio));
}


void 
Crypt_BIO_get_retry_reason(self)
	Crypt_OpenSSL_BIO self;
PPCODE:
{
	XSRETURN_IV(BIO_get_retry_reason(self->bio));
}


##################################################
# These are all specific to different BIOs
##################################################


##################################################
# These relate to descriptor BIOs
##################################################

void
Crypt_BIO_set_fd(self, fd, c = BIO_CLOSE)
	Crypt_OpenSSL_BIO self;
	int fd;
	int c;
PPCODE:
{
	if (c != BIO_CLOSE && c != BIO_NOCLOSE)
		c = BIO_CLOSE;

	// Both file and socket types use this so we just 
	// look to see if the BIO is a descriptor
	if (!(self->bio->method->type & BIO_TYPE_DESCRIPTOR))
		XSRETURN_NO;

	XSRETURN_IV(BIO_set_fd(self->bio, fd, c));
}


void 
Crypt_BIO_get_fd(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
    // Both file and socket types use this so we just
    // look to see if the BIO is a descriptor
    if (!(self->bio->method->type & BIO_TYPE_DESCRIPTOR))
        XSRETURN_NO;

	XSRETURN_IV(BIO_get_fd(self->bio, NULL));
}


void 
Crypt_BIO_new_fd(self, fd, flag = BIO_CLOSE)
	Crypt_OpenSSL_BIO self;
	int fd;
	int flag;
PPCODE:
{
    if (!(self->bio->method->type & BIO_TYPE_DESCRIPTOR))
        XSRETURN_NO;

	if (flag != BIO_CLOSE && flag != BIO_NOCLOSE)
		flag = BIO_CLOSE;

	if ( BIO_new_fd(fd, flag) == NULL)
		XSRETURN_NO;

	self->bio = BIO_new_fd(fd, flag);
	XSRETURN_YES;
}


##################################################
# These relate only to file BIOs
##################################################

void
Crypt_BIO_set_fp(self, fp, c = BIO_CLOSE)
    Crypt_OpenSSL_BIO self;
    int fp;
    int c;
PPCODE:
{
    if (c != BIO_CLOSE && c != BIO_NOCLOSE)
        c = BIO_CLOSE;

    if (self->bio->method->type != BIO_TYPE_FILE)
        XSRETURN_NO;

    BIO_set_fp(self->bio, fp, c);
    XSRETURN_YES;
}


void
Crypt_BIO_get_fp(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
    char *c;

    if (self->bio->method->type != BIO_TYPE_FILE)
        XSRETURN_NO;

    XSRETURN_IV(BIO_get_fp(self->bio, c));
}


void 
Crypt_BIO_change_file(self, file, perms)
	Crypt_OpenSSL_BIO self;
	char * file;
	char * perms;
PPCODE:
{
    if (self->bio->method->type != BIO_TYPE_FILE)
        XSRETURN_NO;

	if (perms == "read")
		XSRETURN_IV(BIO_read_filename(self->bio, file));
	else if (perms == "write")
		XSRETURN_IV(BIO_write_filename(self->bio, file));
	else if (perms == "append")
		XSRETURN_IV(BIO_append_filename(self->bio, file));
	else if (perms == "rw")
		XSRETURN_IV(BIO_rw_filename(self->bio, file));
	else
		XSRETURN_NO;
}


void
Crypt_BIO_new_file(self, filename, mode = "a+")
	Crypt_OpenSSL_BIO self;
	char* filename;
	char* mode;
PPCODE:
{
	if (self->bio->method->type != BIO_TYPE_FILE)
		XSRETURN_NO;

	self->bio = BIO_new_file(filename, mode);
	XSRETURN_YES; 
}


void 
Crypt_BIO_new_fp(self, stream, flags = BIO_NOCLOSE)
	Crypt_OpenSSL_BIO self;
	FILE* stream;
	int flags;
PPCODE:
{
    if (self->bio->method->type != BIO_TYPE_FILE)
        XSRETURN_NO;

	self->bio = BIO_new_fp(stream, flags);
	XSRETURN_YES;
}


##################################################
# This only applies to socket BIOs
##################################################

void 
Crypt_BIO_new_socket(self, sock, flag = BIO_CLOSE)
	Crypt_OpenSSL_BIO self;
	int sock;
	int flag;
PPCODE:
{
	if (self->bio->method->type != BIO_TYPE_SOCKET)
		XSRETURN_NO;

	if (flag != BIO_NOCLOSE && flag != BIO_CLOSE)
		flag = BIO_CLOSE;

	self->bio = BIO_new_socket(sock, flag);
	XSRETURN_YES;
}


##################################################
# These relate to cipher BIOs
##################################################

void 
Crypt_BIO_set_cipher(self, cipher, key = NULL, iv = "INEEDNIV", flag = 1)
	Crypt_OpenSSL_BIO self;
	int cipher;
	unsigned char* key;
	unsigned char* iv;
	int flag;
PPCODE:
{
	void * function;

	switch (cipher){
		case EVP_NULL:				function = EVP_enc_null(); break;

		case EVP_DES_CBC:			function = EVP_des_cbc(); break;
		case EVP_DES_ECB:			function = EVP_des_ecb(); break;
		case EVP_DES_CFB:			function = EVP_des_cfb(); break;
		case EVP_DES_OFB:			function = EVP_des_ofb(); break;

		case EVP_DES_EDE_CBC:		function = EVP_des_ede_cbc(); break;
		case EVP_DES_EDE:			function = EVP_des_ede(); break;
		case EVP_DES_EDE_CFB:		function = EVP_des_ede_cfb(); break;
		case EVP_DES_EDE_OFB:		function = EVP_des_ede_ofb(); break;

		case EVP_DES_EDE3_CBC:		function = EVP_des_ede3_cbc(); break;
		case EVP_DES_EDE3:			function = EVP_des_ede3(); break;
		case EVP_DES_EDE3_CFB:		function = EVP_des_ede3_cfb(); break;
		case EVP_DES_EDE3_OFB:		function = EVP_des_ede3_ofb(); break;
		case EVP_DESX_CBC:			function = EVP_desx_cbc(); break;

		case EVP_RC4:				function = EVP_rc4(); break;

		case EVP_IDEA_CBC:			function = EVP_idea_cbc(); break;
		case EVP_IDEA_ECB:			function = EVP_idea_ecb(); break;
		case EVP_IDEA_CFB:			function = EVP_idea_cfb(); break;
		case EVP_IDEA_OFB:			function = EVP_idea_ofb(); break;

		case EVP_RC2_CBC:			function = EVP_rc2_cbc(); break;
		case EVP_RC2_ECB:			function = EVP_rc2_ecb(); break;
		case EVP_RC2_CFB:			function = EVP_rc2_cfb(); break;
		case EVP_RC2_OFB:			function = EVP_rc2_ofb(); break;

		case EVP_BF_CBC:			function = EVP_bf_cbc(); break;
		case EVP_BF_ECB:			function = EVP_bf_ecb(); break;
		case EVP_BF_CFB:			function = EVP_bf_cfb(); break;
		case EVP_BF_OFB:			function = EVP_bf_ofb(); break;

		case EVP_CAST5_CBC:			function = EVP_cast5_cbc(); break;
		case EVP_CAST5_ECB:			function = EVP_cast5_ecb(); break;
		case EVP_CAST5_CFB:			function = EVP_cast5_cfb(); break;
		case EVP_CAST5_OFB:			function = EVP_cast5_ofb(); break;

		case EVP_RC5_32_12_16_CBC:	function = EVP_rc5_32_12_16_cbc(); break;
		case EVP_RC5_32_12_16_ECB:	function = EVP_rc5_32_12_16_ecb(); break;
        case EVP_RC5_32_12_16_CFB:  function = EVP_rc5_32_12_16_cfb(); break;
        case EVP_RC5_32_12_16_OFB:  function = EVP_rc5_32_12_16_ofb(); break;

		default:					function = EVP_enc_null(); break;
	}

	self->enc->cipher = function;

	if (key != NULL)
		memcpy(self->enc->key, key, EVP_MAX_KEY_LENGTH);

	if (iv != NULL)
		memcpy(self->enc->iv, iv, EVP_MAX_IV_LENGTH);

	// These ciphers do not use IV so we just zero it out, 
	// or maybe I screwed something up which is entirely 
	// possible.
	if (cipher == EVP_DES_EDE3_OFB || cipher == EVP_RC2_CFB)
		memset(self->enc->iv, 0, sizeof(unsigned char));

	// Not sure why this doesn't take an 8-byte key, 
	// but this works so until I figure it out... 
	if (cipher == EVP_DES_ECB && strlen(key) > 4){
		memset(self->enc->key, 0, EVP_MAX_KEY_LENGTH);
		memcpy(self->enc->key, key, 4);
	}


	BIO_set_cipher(self->bio, self->enc->cipher, self->enc->key, self->enc->iv, flag);
	XSRETURN_YES;
}


##################################################
# encrypt/decrypt are not part of the openssl 
# specification. They are mostly convenience 
# functions so you don't have to keep calling 
# set_cipher() over and over.
##################################################

void
Crypt_BIO_encrypt(self, data)
	Crypt_OpenSSL_BIO self;
	char * data;
PPCODE:
{
 	if (self->enc->cipher == NULL)
		croak("Encryption BIO must be set up via set_cipher()\n");

    BIO_set_cipher(self->bio, self->enc->cipher, self->enc->key, self->enc->iv, 1);
	XSRETURN_IV(write_data(self, data, "write"));
}


void
Crypt_BIO_decrypt(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
     if (self->enc->cipher == NULL)
        croak("Encryption BIO must be set up via set_cipher()\n");

    BIO_set_cipher(self->bio, self->enc->cipher, self->enc->key, self->enc->iv, 0);

	XPUSHs(read_data(self, "read"));
    XSRETURN(1);
}


##################################################
# This is suppose to return whether or not 
# decryption was successful. No matter how I tried
# to make it fail, I always get a 1 back?
##################################################

void 
Crypt_BIO_get_cipher_status(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
	if (self->bio->method->type != BIO_TYPE_CIPHER)
		XSRETURN_NO;

	XSRETURN_IV(BIO_get_cipher_status(self->bio));
}


##################################################
# Way to manually manipulate the flags should the 
# need arise.
##################################################

void Crypt_BIO_set_flags(self, flags)
	Crypt_OpenSSL_BIO self;
	int flags;
PPCODE:
{
	BIO_set_flags(self->bio, flags);
	XSRETURN_YES;
}


void Crypt_BIO_get_flags(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
	int flags = BIO_get_flags(self->bio);

	if (flags)
		XSRETURN_IV(BIO_get_flags(self->bio));
	else
		XSRETURN_IV(0);
}


##################################################
# All of these apply to memory BIOs
##################################################

void 
Crypt_BIO_set_mem_eof_return(self, flag)
	Crypt_OpenSSL_BIO self;
	int flag;
PPCODE:
{
	if (self->bio->method->type != BIO_TYPE_MEM)
		XSRETURN_NO;

	BIO_set_mem_eof_return(self->bio, flag);
	XSRETURN_YES;
}


##################################################
# This mimics the BIO_new_mem_buf() behaviour
##################################################

void
Crypt_BIO_set_read_only(self, data)
    Crypt_OpenSSL_BIO self;
	char *data;
PPCODE:
{
    if (self->bio->method->type != BIO_TYPE_MEM)
        XSRETURN_NO;

	self->bio = BIO_new_mem_buf((void *)data, strlen(data));
	XSRETURN_YES;
}


##################################################
# These relate to buffer BIOs.
##################################################

void
Crypt_BIO_get_num_lines(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
	if (self->bio->method->type != BIO_TYPE_BUFFER)
		XSRETURN_NO;

	XSRETURN_IV(BIO_get_buffer_num_lines(self->bio));
}


void
Crypt_BIO_set_size(self, size, type = NULL)
    Crypt_OpenSSL_BIO self;
	int size;
	char * type;
PPCODE:
{
    if (self->bio->method->type != BIO_TYPE_BUFFER)
        XSRETURN_NO;

	if (type == NULL)
		XSRETURN_IV(BIO_set_buffer_size(self->bio, size));
	else if (type == "read")
		XSRETURN_IV(BIO_set_read_buffer_size(self->bio, size));
	else if (type == "write")
		XSRETURN_IV(BIO_set_write_buffer_size(self->bio, size));
	else
		XSRETURN_NO;
}


##################################################
# These all relate to digest (md) BIOs
##################################################

void 
Crypt_BIO_set_md(self, type)
	Crypt_OpenSSL_BIO self;
	int type;
PPCODE:
{
	void * function;

	if (self->bio->method->type != BIO_TYPE_MD)
        XSRETURN_NO;

	switch (type){
		case EVP_MD2:		function = EVP_md2(); break;
		case EVP_MD5:		function = EVP_md5(); break;
		case EVP_MDC2:		function = EVP_mdc2(); break;
		case EVP_SHA:		function = EVP_sha(); break;
		case EVP_SHA1:		function = EVP_sha1(); break;
	}

	if (function == NULL)
		croak("Incorrect digest method");

	XSRETURN_IV(BIO_set_md(self->bio, function));
}


##################################################
# Returns the actual digested data and not the 
# binary representation.
##################################################

void
Crypt_BIO_read_md(self)
    Crypt_OpenSSL_BIO self;
PPCODE:
{
    char *md, *temp;
    unsigned char mbuf[EVP_MAX_MD_SIZE];
    int i, len;

    if (New(0, md, self->buflen+1, char) == NULL)
        noAlloc();

    if (New(0, temp, self->buflen+1, char) == NULL)
        noAlloc();

    memset(md, 0, self->buflen+1);
    memset(temp, 0, self->buflen+1);

    len = BIO_gets(self->bio, mbuf, EVP_MAX_MD_SIZE);

    for (i = 0; i < len; i++)
    {
        sprintf(md, "%02X", mbuf[i]);
        strcat(temp, md);
    }

    XPUSHs(sv_2mortal(newSVpvn(temp, strlen(temp))));

    Safefree(md);
    Safefree(temp);

    XSRETURN(1);
}


##################################################
# These all relate to connect BIOs
##################################################

void 
Crypt_BIO_hostname(self, name = NULL)
	Crypt_OpenSSL_BIO self;
	char* name;
PPCODE:
{
	if (self->bio->method->type != BIO_TYPE_CONNECT)
		XSRETURN_NO;

	if (name == NULL)
		XSRETURN_PV(BIO_get_conn_hostname(self->bio));

	XSRETURN_IV(BIO_set_conn_hostname(self->bio, name));
}


##################################################
# Rolling this to handle both connect/accept BIOs
##################################################

void 
Crypt_BIO_port(self, port = NULL)
	Crypt_OpenSSL_BIO self;
	char* port;
PPCODE:
{
    if (self->bio->method->type == BIO_TYPE_CONNECT)
	{
    	if (port == NULL)
        	XSRETURN_PV(BIO_get_conn_port(self->bio));

    	XSRETURN_IV(BIO_set_conn_port(self->bio, port));
	}
	else if (self->bio->method->type == BIO_TYPE_ACCEPT)
	{
        if (port == NULL)
            XSRETURN_PV(BIO_get_accept_port(self->bio));

        XSRETURN_IV(BIO_set_accept_port(self->bio, port));
	}
	else
	{
		XSRETURN_NO;
	}
}


##################################################
# For some reason I can't get this to work so we 
# will just use the hostname to connect up.
##################################################

void 
Crypt_BIO_ip(self, ip = NULL)
    Crypt_OpenSSL_BIO self;
    char* ip;
PPCODE:
{
    if (self->bio->method->type != BIO_TYPE_CONNECT)
        XSRETURN_NO;

	XSRETURN_NO;
}


##################################################
# Roll this to work with connect/accept BIOs
##################################################

void 
Crypt_BIO_nbio(self, n)
	Crypt_OpenSSL_BIO self;
	int n;
PPCODE:
{
    if (self->bio->method->type == BIO_TYPE_CONNECT)
		XSRETURN_IV(BIO_set_nbio(self->bio, n));
	else if (self->bio->method->type == BIO_TYPE_ACCEPT)
		XSRETURN_IV(BIO_set_nbio_accept(self->bio, n));
	else
		XSRETURN_NO;
}


void
Crypt_BIO_do_connect(self)
	Crypt_OpenSSL_BIO self;
PPCODE:
{
    if (self->bio->method->type != BIO_TYPE_CONNECT)
        XSRETURN_NO;

	XSRETURN_IV(BIO_do_connect(self->bio));
}


void 
Crypt_BIO_new_connect(self, loc)
	Crypt_OpenSSL_BIO self;
	char* loc;
PPCODE:
{
    if (self->bio->method->type != BIO_TYPE_CONNECT)
        XSRETURN_NO;

	self->bio = BIO_new_connect(loc);
	XSRETURN_YES;
}


##################################################
# These all relate to accept BIOs
##################################################

void 
Crypt_BIO_new_accept(self, host)
	Crypt_OpenSSL_BIO self;
	char* host;
PPCODE:
{
	if (self->bio->method->type != BIO_TYPE_ACCEPT)
		XSRETURN_NO;

	self->bio = BIO_new_accept(host);
	XSRETURN_YES;
}


##################################################
# Can't get this to work
##################################################

void 
Crypt_BIO_accept_bios(self, bio)
	Crypt_OpenSSL_BIO self;
	Crypt_OpenSSL_BIO bio;
PPCODE:
{
	XSRETURN_NO;

    if (self->bio->method->type != BIO_TYPE_ACCEPT)
        XSRETURN_NO;

	XSRETURN_IV(BIO_set_accept_bios(self->bio, bio->bio));
}


void 
Crypt_BIO_bind_mode(self, mode = -9)
	Crypt_OpenSSL_BIO self;
	int mode;
PPCODE:
{
    if (self->bio->method->type != BIO_TYPE_ACCEPT)
        XSRETURN_NO;

	if (mode == -9)
		XSRETURN_IV(BIO_get_bind_mode(self->bio, NULL));
	else
		XSRETURN_IV(BIO_set_bind_mode(self->bio, mode));
}


void 
Crypt_BIO_do_accept(self)
	Crypt_OpenSSL_BIO self;
PPCODE:
{
    if (self->bio->method->type != BIO_TYPE_ACCEPT)
        XSRETURN_NO;

	XSRETURN_IV(BIO_do_accept(self->bio));
}





