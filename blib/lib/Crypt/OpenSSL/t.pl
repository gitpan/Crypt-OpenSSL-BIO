#!/usr/bin/perl

  use Data::Dumper;

  my $text = "This is some longer data to test memory allocation.";
  my $data;

#my $text = "This is some text to test the module with. Let's hope it works.";

  use Crypt::OpenSSL::BIO qw(:all);

  my $c = new Crypt::OpenSSL::BIO(BIO_TYPE_CIPHER);
  my $m = new Crypt::OpenSSL::BIO(BIO_TYPE_MEM);

  $c->set_cipher(EVP_BF_ECB, "1as2w3d4");
  $c->push($m);

  print decrypt(encrypt($text));



  sub encrypt {
      my $data = shift;
      $data .= chr(13)x(8-(length($data)%8));
      my $temp;

      for (my $x = 0; $x < length($data); $x+=8){
          $c->encrypt(substr($data, $x, 8));
          $c->flush;
          $temp .= $m->read;
      }

      return $temp;
  }


  sub decrypt {
      my $data = shift;
      my $temp;

      for (my $x = 0; $x < length($data); $x+=8){
          $m->write(substr($data, $x, 8));
          $m->flush;

          $temp .= $c->decrypt;

      }

      return $temp;
  }



