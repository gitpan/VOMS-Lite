#!/usr/bin/perl

# propagate version numbers

use Cwd;
BEGIN {
  unshift @INC, "./lib";
  eval { require VOMS::Lite; };
}
use File::Find;
my $dir=getcwd;

print "About to change Version to $VOMS::Lite::VERSION\n";

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

print "$dir/misc/perl-VOMS-Lite.spec\n";
open (OLD,"<$dir/misc/perl-VOMS-Lite.spec")        or die "couldn't open perl-VOMS-Lite.spec for reading";
open (NEW,">$dir/misc/perl-VOMS-Lite.spec.new")    or die "couldn't open perl-VOMS-Lite.spec.new for reading";

while (<OLD>) {
  s/^\s*Version:\s*\d[\d.]*\s*$/Version:        $VOMS::Lite::VERSION\n/;
  print NEW $_;
}
close OLD;
close NEW;
rename "$dir/misc/perl-VOMS-Lite.spec.new", "$dir/misc/perl-VOMS-Lite.spec";


