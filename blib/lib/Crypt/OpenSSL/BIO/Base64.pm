  package Crypt::OpenSSL::BIO::Base64;

  use strict;

  use Crypt::OpenSSL::BIO qw(
		BIO_TYPE_BASE64 
		BIO_TYPE_MEM 
		BIO_CLOSE 
		BIO_FLAGS_BASE64_NO_NL
  );

  our $VERSION = '0.01';

  sub new {
      my $class = shift;

      my $self = bless {
			base64 => new Crypt::OpenSSL::BIO(BIO_TYPE_BASE64),
			mem => new Crypt::OpenSSL::BIO(BIO_TYPE_MEM),
      }, ref $class || $class;

      $self->{base64}->set_flags(BIO_FLAGS_BASE64_NO_NL);
      $self->{mem}->close(BIO_CLOSE);
      $self->{base64}->push($self->{mem});

      return $self;
  }


  sub encode {
      my $self = shift;
      $self->{mem}->reset;
      $self->{base64}->write(shift());
      $self->{base64}->flush;
      return $self->{mem}->read;
  }


  sub decode {
      my $self = shift;
      $self->{mem}->reset;
      $self->{mem}->write(shift());
      $self->{mem}->flush;
      return $self->{base64}->read;
  }


  sub DESTROY {
      shift()->{base64}->free_all;
  }


1;
__END__

