  package Crypt::OpenSSL::BIO::ECB::RC5_32_12_16;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_RC5_32_12_16_ECB);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_RC5_32_12_16_ECB, @_);
  }


1;
__END__

