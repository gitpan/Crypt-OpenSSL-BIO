  package Crypt::OpenSSL::BIO::ECB::DES2;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_DES_EDE_ECB);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_DES_EDE_ECB, @_);
  }


1;
__END__

