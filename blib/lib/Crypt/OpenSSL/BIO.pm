  package Crypt::OpenSSL::BIO;

  use strict;
  require Exporter;
  require DynaLoader;

  our @ISA = qw(Exporter DynaLoader);
  our $VERSION = '0.01';


  # Most of these are directly from bio.h
  use constant BIO_TYPE_DESCRIPTOR  => 0x0100;
  use constant BIO_TYPE_FILTER      => 0x0200;
  use constant BIO_TYPE_SOURCE_SINK => 0x0400;

  use constant BIO_TYPE_NONE		=> 0;
  use constant BIO_TYPE_MEM			=> (1|BIO_TYPE_SOURCE_SINK);
  use constant BIO_TYPE_FILE		=> (2|BIO_TYPE_SOURCE_SINK);
  use constant BIO_TYPE_FD			=> (4|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR);
  use constant BIO_TYPE_SOCKET		=> (5|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR);
  use constant BIO_TYPE_NULL		=> (6|BIO_TYPE_SOURCE_SINK);
  use constant BIO_TYPE_MD			=> (8|BIO_TYPE_FILTER);
  use constant BIO_TYPE_BUFFER		=> (9|BIO_TYPE_FILTER);
  use constant BIO_TYPE_CIPHER		=> (10|BIO_TYPE_FILTER);
  use constant BIO_TYPE_BASE64		=> (11|BIO_TYPE_FILTER);
  use constant BIO_TYPE_CONNECT		=> (12|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR);
  use constant BIO_TYPE_ACCEPT		=> (13|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR);
  use constant BIO_TYPE_NULL_FILTER	=> (17|BIO_TYPE_FILTER);

  use constant BIO_CLOSE	=> 0x01;
  use constant BIO_NOCLOSE	=> 0x00;

  use constant BIO_FLAGS_READ			=> 0x01;
  use constant BIO_FLAGS_WRITE			=> 0x02;
  use constant BIO_FLAGS_IO_SPECIAL		=> 0x04;
  use constant BIO_FLAGS_RWS			=> (BIO_FLAGS_READ|BIO_FLAGS_WRITE|BIO_FLAGS_IO_SPECIAL);
  use constant BIO_FLAGS_SHOULD_RETRY	=> 0x08;
  use constant BIO_FLAGS_NO_SINK		=> 0x99;  # This one isn't defined in bio.h 
  use constant BIO_FLAGS_BASE64_NO_NL   => 0x100;

  use constant EVP_NULL				=> 0;

  use constant EVP_DES_CBC			=> 1;
  use constant EVP_DES_ECB			=> 2;
  use constant EVP_DES_CFB			=> 3;
  use constant EVP_DES_OFB			=> 4;

  use constant EVP_DES_EDE_CBC		=> 5;
  use constant EVP_DES_EDE			=> 6;
  use constant EVP_DES_EDE_CFB		=> 7;
  use constant EVP_DES_EDE_OFB		=> 8;

  use constant EVP_DES_EDE3_CBC		=> 9;
  use constant EVP_DES_EDE3			=> 10;
  use constant EVP_DES_EDE3_CFB		=> 11;
  use constant EVP_DES_EDE3_OFB		=> 12;

  use constant EVP_DESX_CBC			=> 13;

  use constant EVP_RC4				=> 20;

  use constant EVP_IDEA_CBC			=> 30;
  use constant EVP_IDEA_ECB			=> 31;
  use constant EVP_IDEA_CFB			=> 32;
  use constant EVP_IDEA_OFB			=> 33;

  use constant EVP_RC2_CBC			=> 40;
  use constant EVP_RC2_ECB			=> 41;
  use constant EVP_RC2_CFB			=> 42;
  use constant EVP_RC2_OFB			=> 43;

  use constant EVP_BF_CBC			=> 50;
  use constant EVP_BF_ECB			=> 51;
  use constant EVP_BF_CFB			=> 52;
  use constant EVP_BF_OFB			=> 53;

  use constant EVP_CAST5_CBC		=> 60;
  use constant EVP_CAST5_ECB		=> 61;
  use constant EVP_CAST5_CFB		=> 62;
  use constant EVP_CAST5_OFB		=> 63;

  use constant EVP_RC5_32_12_16_CBC	=> 70;
  use constant EVP_RC5_32_12_16_ECB	=> 71;
  use constant EVP_RC5_32_12_16_CFB	=> 72;
  use constant EVP_RC5_32_12_16_OFB	=> 73;

  use constant EVP_MD2		=> 1000;
  use constant EVP_MD5		=> 1001;
  use constant EVP_MDC2		=> 1002;
  use constant EVP_SHA		=> 1003;
  use constant EVP_SHA1		=> 1004;

  use constant BIO_BIND_NORMAL				=> 0;
  use constant BIO_BIND_REUSEADDR_IF_UNUSED	=> 1;
  use constant BIO_BIND_REUSEADDR			=> 2;


  our @FLAGS = qw(BIO_FLAGS_READ BIO_FLAGS_WRITE BIO_FLAGS_IO_SPECIAL BIO_FLAGS_RWS
                  BIO_FLAGS_SHOULD_RETRY BIO_FLAGS_BASE64_NO_NL BIO_FLAGS_NO_SINK);

  our @TYPES = qw(BIO_TYPE_NONE BIO_TYPE_MEM BIO_TYPE_FILE BIO_TYPE_FD BIO_TYPE_SOCKET
                  BIO_TYPE_NULL BIO_TYPE_MD BIO_TYPE_BUFFER BIO_TYPE_CIPHER BIO_TYPE_BASE64
                  BIO_TYPE_CONNECT BIO_TYPE_ACCEPT BIO_TYPE_NULL_FILTER); 

  our @BASE_TYPES = qw(BIO_TYPE_FILTER BIO_TYPE_DESCRIPTOR BIO_TYPE_SOURCE_SINK);

  our @OP = qw(BIO_CLOSE BIO_NOCLOSE);

  our @ENC = qw( EVP_NULL EVP_DES_CBC EVP_DES_ECB EVP_DES_CFB EVP_DES_OFB EVP_DES_EDE_CBC 
				 EVP_DES_EDE EVP_DES_EDE_CFB EVP_DES_EDE_OFB EVP_DES_EDE3_CBC EVP_DES_EDE3 
				 EVP_DES_EDE3_CFB EVP_DES_EDE3_OFB EVP_DESX_CBC EVP_RC4 EVP_IDEA_CBC EVP_IDEA_ECB 
                 EVP_IDEA_CFB EVP_IDEA_OFB EVP_RC2_CBC EVP_RC2_ECB EVP_RC2_CFB EVP_RC2_OFB 
                 EVP_BF_CBC EVP_BF_ECB EVP_BF_CFB EVP_BF_OFB EVP_CAST5_CBC EVP_CAST5_ECB 
                 EVP_CAST5_CFB EVP_CAST5_OFB EVP_RC5_32_12_16_CBC EVP_RC5_32_12_16_ECB 
                 EVP_RC5_32_12_16_CFB EVP_RC5_32_12_16_OFB );

  our @MD = qw( EVP_MD2 EVP_MD5 EVP_MDC2 EVP_RMD160 EVP_SHA EVP_SHA1 );
  our @BIND = qw(BIO_BIND_NORMAL BIO_BIND_REUSEADDR_IF_UNUSED BIO_BIND_REUSEADDR);

  our @EXPORT = (); 
  our @EXPORT_OK = (@FLAGS, @TYPES, @OP, @ENC, @MD, @BIND, @BASE_TYPES);

  our %EXPORT_TAGS = (
		all => [@EXPORT_OK, @EXPORT],
		bio_flags	=> [@FLAGS],
		bio_types	=> [@TYPES],
		base_types	=> [@BASE_TYPES],
		ops			=> [@OP],
		encrypt		=> [@ENC],
		digest		=> [@MD],
		socks		=> [@BIND],
  );

  bootstrap Crypt::OpenSSL::BIO $VERSION;


1;
__END__

