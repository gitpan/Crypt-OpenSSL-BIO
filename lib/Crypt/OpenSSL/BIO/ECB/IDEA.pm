  package Crypt::OpenSSL::BIO::ECB::IDEA;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_IDEA_ECB);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_IDEA_ECB, @_);
  }


1;
__END__

