  package Crypt::OpenSSL::BIO::CFB::Blowfish;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_BF_CFB);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_BF_CFB, @_);
  }


1;
__END__

