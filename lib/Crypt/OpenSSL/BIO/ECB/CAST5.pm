  package Crypt::OpenSSL::BIO::ECB::CAST5;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_CAST5_ECB);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_CAST5_ECB, @_);
  }


1;
__END__

