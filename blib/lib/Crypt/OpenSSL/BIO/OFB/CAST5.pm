  package Crypt::OpenSSL::BIO::OFB::CAST5;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_CAST5_OFB);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_CAST5_OFB, @_);
  }


1;
__END__

