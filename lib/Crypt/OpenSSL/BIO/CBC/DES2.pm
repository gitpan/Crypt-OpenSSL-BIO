  package Crypt::OpenSSL::BIO::CBC::DES2;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_DES_EDE_CBC);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_DES_EDE_CBC, @_);
  }


1;
__END__

