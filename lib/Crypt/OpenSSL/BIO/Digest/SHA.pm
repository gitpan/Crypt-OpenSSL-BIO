  package Crypt::OpenSSL::BIO::Digest::SHA;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_SHA);
  use base qw(Crypt::OpenSSL::BIO::Digest);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_SHA, @_);
  }


1;
__END__


