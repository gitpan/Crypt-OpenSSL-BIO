  package Crypt::OpenSSL::BIO::Digest::MD2;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_MD2);
  use base qw(Crypt::OpenSSL::BIO::Digest);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_MD2, @_);
  }


1;
__END__


