  package Crypt::OpenSSL::BIO::CFB::IDEA;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_IDEA_CFB);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_IDEA_CFB, @_);
  }


1;
__END__

