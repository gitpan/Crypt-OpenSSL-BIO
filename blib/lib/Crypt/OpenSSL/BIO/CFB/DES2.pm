  package Crypt::OpenSSL::BIO::CFB::DES2;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_DES_EDE_CFB);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_DES_EDE_CFB, @_);
  }


1;
__END__

