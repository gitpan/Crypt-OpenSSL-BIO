  package Crypt::OpenSSL::BIO::CFB::DES3;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_DES_EDE3_CFB);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_DES_EDE3_CFB, @_);
  }


1;
__END__

