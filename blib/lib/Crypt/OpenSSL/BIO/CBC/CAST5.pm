  package Crypt::OpenSSL::BIO::CBC::CAST5;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_CAST5_CBC);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_CAST5_CBC, @_);
  }


1;
__END__

