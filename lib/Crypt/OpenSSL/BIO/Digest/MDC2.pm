  package Crypt::OpenSSL::BIO::Digest::MDC2;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_MDC2);
  use base qw(Crypt::OpenSSL::BIO::Digest);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_MDC2, @_);
  }


1;
__END__


