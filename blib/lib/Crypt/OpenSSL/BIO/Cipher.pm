  package Crypt::OpenSSL::BIO::Cipher;

  use strict;
  use Crypt::OpenSSL::BIO qw(:encrypt BIO_TYPE_CIPHER BIO_TYPE_MEM BIO_CLOSE);
  our $VERSION = '0.01';

  sub new {
      my $class = shift;
      my ($type, $key, $iv) = @_;

      $key ||= '';
      $iv ||= '';

      my $self = bless {
			cipher => new Crypt::OpenSSL::BIO(BIO_TYPE_CIPHER),
			mem => new Crypt::OpenSSL::BIO(BIO_TYPE_MEM),
      }, ref $class || $class;

      $self->{mem}->close(BIO_CLOSE);
      $self->{cipher}->set_cipher($type, $key, $iv);
      $self->{cipher}->push($self->{mem});

      return $self;
  }


  sub encrypt {
      my $self = shift;
      $self->{cipher}->reset;
      $self->{cipher}->encrypt(shift());
      $self->{cipher}->flush;
      return $self->{mem}->read;
  }


  sub decrypt {
      my $self = shift;
      $self->{mem}->reset;
      $self->{mem}->write(shift());
      $self->{mem}->flush;
      return $self->{cipher}->decrypt;
  }


##################################################
# This is needed for the ECB and CBC modes
##################################################

  sub pad {
      return $_[1].chr(13)x(8-(length($_[1])%8));
  }


  sub unpad {
      (my $data = $_[1]) =~ s/@{[chr(13)]}//g;
      return $data;
  }


  sub DESTROY {
      shift()->{cipher}->free_all;
  }


1;
__END__


