use ExtUtils::MakeMaker;
use Config;

WriteMakefile(
    'NAME'			=> 'Crypt::OpenSSL::BIO',
    'DISTNAME'		=> 'Crypt-OpenSSL-BIO',
    'VERSION_FROM'	=> 'lib/Crypt/OpenSSL/BIO.pm',
	'AUTHOR'		=> 'Shay Harding <sharding@ccbill.com>',
	'ABSTRACT'		=> 'Interface to openssl 0.9.6c BIO functions',
    'OBJECT'		=> '$(O_FILES)',
    'LIBS'			=> ['-lcrypto'],
    'PREREQ_PM'		=> { },
    'DEFINE'		=> '',
    'INC'			=> '',
	'dist'			=> { COMPRESS => "gzip -9", SUFFIX => "gz" }
);
