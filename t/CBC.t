#!perl -w

use strict;
no strict "vars";

my @enc = qw(Blowfish CAST5 DES2 DES3 DES IDEA RC2 RC5_32_12_16);
my $text = "This is some text to test the module with. Let's hope it works.";

print "1..".@enc."\n"; 
my $n = 1;


for (@enc){
    my $mod = "Crypt::OpenSSL::BIO::CBC::$_";
    eval "use $mod('password')";
    my $c = new $mod;

    my $data = $c->unpad($c->decrypt($c->encrypt($c->pad($text))));

    if ($data eq $text) { print "ok $n\n"; } else { print "not ok $n\n"; }
    $n++;
}


__END__

