  package Crypt::OpenSSL::BIO::CFB::RC2;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_RC2_CFB);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_RC2_CFB, @_);
  }


1;
__END__

