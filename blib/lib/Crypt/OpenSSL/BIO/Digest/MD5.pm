  package Crypt::OpenSSL::BIO::Digest::MD5;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_MD5);
  use base qw(Crypt::OpenSSL::BIO::Digest);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_MD5, @_);
  }


1;
__END__


