#!/usr/bin/perl

  my $ver = "0.01";
  `./build_manifest.pl`;

  open FILE, "../MANIFEST";
  my $str;

  for (<FILE>){
      chomp;
      $str .= "./Crypt-OpenSSL-BIO-$ver/$_ ";
  }

  `tar -C ../.. -zcf Crypt-OpenSSL-BIO-$ver.tar.gz $str`;
  `mv Crypt-OpenSSL-BIO-$ver.tar.gz ../`;
  close FILE;
