#!perl -w

use strict;
no strict "vars";

use Crypt::OpenSSL::BIO qw(:bio_types BIO_CLOSE BIO_NOCLOSE);

my @temp = @Crypt::OpenSSL::BIO::TYPES[1..$#Crypt::OpenSSL::BIO::TYPES];
print "1..".(@temp*11)."\n"; 
my $n = 1;

for (@temp){
    my $obj = new Crypt::OpenSSL::BIO(eval "Crypt::OpenSSL::BIO::$_");
    if (ref($obj) eq 'Crypt::OpenSSL::BIO') { print "ok $n\n"; } else { print "not ok $n\n"; }
    $n++;
	if ($obj->type eq (eval "Crypt::OpenSSL::BIO::$_")) { print "ok $n\n"; } else { print "not ok $n\n"; }
    $n++;
    if ($obj->buflen == 1024) { print "ok $n\n"; } else { print "not ok $n\n"; }
    $n++;
    $obj->buflen(512);
    if ($obj->buflen == 512) { print "ok $n\n"; } else { print "not ok $n\n"; }
    $n++;
    $obj->set(BIO_TYPE_MEM);
    if ($obj->type == BIO_TYPE_MEM) { print "ok $n\n"; } else { print "not ok $n\n"; }
    $n++;
    my $close = $obj->close(-1);
    if ($close == BIO_CLOSE || $close == BIO_NOCLOSE) { print "ok $n\n"; } else { print "not ok $n\n"; }
    $n++;
    if ($obj->close(BIO_CLOSE)) { print "ok $n\n"; } else { print "not ok $n\n"; }
    $n++;
    if ($obj->close(-1) == BIO_CLOSE) { print "ok $n\n"; } else { print "not ok $n\n"; }
    $n++;
    if ($obj->close(BIO_NOCLOSE)) { print "ok $n\n"; } else { print "not ok $n\n"; }
    $n++;
    if ($obj->close(-1) == BIO_NOCLOSE) { print "ok $n\n"; } else { print "not ok $n\n"; }
    $n++;
    if ($obj->free) { print "ok $n\n"; } else { print "not ok $n\n"; }
    $n++;
}


__END__

