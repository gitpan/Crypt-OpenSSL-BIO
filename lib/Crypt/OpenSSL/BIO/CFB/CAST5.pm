  package Crypt::OpenSSL::BIO::CFB::CAST5;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_CAST5_CFB);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_CAST5_CFB, @_);
  }


1;
__END__

