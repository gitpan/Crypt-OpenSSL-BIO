  package Crypt::OpenSSL::BIO::CBC::Blowfish;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_BF_CBC);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_BF_CBC, @_);
  }


1;
__END__

