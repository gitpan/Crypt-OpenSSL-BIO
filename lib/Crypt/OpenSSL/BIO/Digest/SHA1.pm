  package Crypt::OpenSSL::BIO::Digest::SHA1;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_SHA1);
  use base qw(Crypt::OpenSSL::BIO::Digest);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_SHA1, @_);
  }


1;
__END__


