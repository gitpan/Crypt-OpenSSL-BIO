  package Crypt::OpenSSL::BIO::CBC::IDEA;

  use strict;
  use Crypt::OpenSSL::BIO qw(EVP_IDEA_CBC);
  use base qw (Crypt::OpenSSL::BIO::Cipher);
  our $VERSION = '0.01';

  sub new {
      shift()->SUPER::new(EVP_IDEA_CBC, @_);
  }


1;
__END__

