  package Crypt::OpenSSL::BIO::Digest;

  use strict;
  use Crypt::OpenSSL::BIO qw(:digest BIO_TYPE_MD BIO_TYPE_MEM BIO_CLOSE);
  our $VERSION = '0.01';


  sub new {
      my $class = shift;
      my ($type) = @_;

      my $self = bless {
			md => new Crypt::OpenSSL::BIO(BIO_TYPE_MD),
			mem => new Crypt::OpenSSL::BIO(BIO_TYPE_MEM),
      }, ref $class || $class;

      $self->{mem}->close(BIO_CLOSE);
      $self->{md}->set_md($type);
      $self->{md}->push($self->{mem});

      return $self; 
  }


  sub digest {
      my $self = shift;
      $self->{mem}->reset;
      $self->{mem}->write(shift());
      $self->{mem}->flush;
      $self->{md}->read;
      return $self->{md}->read_md;
  }


  sub DESTROY {
      shift()->{md}->free_all;
  }


1;
__END__

