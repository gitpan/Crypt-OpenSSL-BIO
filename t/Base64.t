#!perl -w

use strict;
no strict "vars";

use Crypt::OpenSSL::BIO::Base64;
my $b = new Crypt::OpenSSL::BIO::Base64;
my $text = "This is some text to test the module with. Let's hope it works.";

print "1..1\n"; 
my $n = 1;

if ($b->decode($b->encode($text)) eq $text) { print "ok $n\n"; } else { print "not ok $n\n"; }


__END__

