  package Crypt::OpenSSL::BIO::OFB::RC2;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_RC2_OFB);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_RC2_OFB, @_);
  }


1;
__END__

