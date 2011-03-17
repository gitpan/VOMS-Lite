#!/usr/bin/perl

# propagate version numbers

BEGIN {
  unshift @INC, "./lib";
}

use VOMS::Lite;
use File::Find;
use Cwd;

my $dir=getcwd;

find(\&wanted, "$dir/lib/VOMS/Lite");

sub wanted { 
  if (/\.pm$/) { 
    print "$File::Find::name\n"; 
    open (OLD,"<$File::Find::name")        or die "couldn't open $File::Find::name for reading";
    open (NEW,">$File::Find::name".".new")  or die "couldn't open $File::Find::name for writing";
    while (<OLD>) {
      s/^\s*\$VERSION\s*=\s*'\d[\d.]*';\s*$/\$VERSION = '$VOMS::Lite::VERSION';\n/;
      print NEW $_;
    }
    close OLD;
    close NEW;
    rename "$File::Find::name".".new", "$File::Find::name";
  }
}
