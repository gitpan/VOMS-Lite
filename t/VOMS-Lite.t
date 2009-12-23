# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl VOMS-Lite.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Cwd;
use Test;
use Sys::Hostname;
my $host = hostname;

BEGIN { plan tests => 20 };

my $cwd = getcwd;
my $etc="$cwd/etc";
my $capath="$etc/certificates";

if ( ! -d $etc ) { mkdir($etc) or die "no test etc directory"; }
if ( ! -d $capath ) { mkdir($capath) or die "no test etc/certificates directory"; }

#Make CA cert here
eval "require VOMS::Lite::X509"; if ($@) { ok(0); print STDERR "$@"; } else { ok(1); }

my %CA = %{ VOMS::Lite::X509::Create( { Serial=>0,
                                            DN=>["C=ACME","O=VOMS::Lite","CN=VOMS::Lite Test CA"],
                                            CA=>"True",
                                          Bits=>512,
                                      Lifetime=>172800 } ) };

if (defined $CA{Cert} &&  defined $CA{Key} && ! defined $CA{Errors} ) { ok(1); } else { ok(0); print STDERR "Not Able to create a CA certificate\n" }
eval "require VOMS::Lite::PEMHelper"; if ($@) { ok(0); print STDERR "$@"; } else { ok(1); }
my $CAcert="$capath/$CA{'Hash'}.0";
my $CAkey="$capath/$CA{'Hash'}.k0";
eval { VOMS::Lite::PEMHelper::writeCert("$CAcert", $CA{'Cert'});          }; if ($@) { ok(0); print STDERR "$@"; } else { ok(1); }
eval { VOMS::Lite::PEMHelper::writeKey("$CAkey", $CA{'Key'}, 'testpass'); }; if ($@) { ok(0); print STDERR "$@"; } else { ok(1); }

#Make host certificate here
my %host = %{ VOMS::Lite::X509::Create( { Serial=>1,
                                          CACert=>$CA{'Cert'},
                                           CAKey=>$CA{'Key'},
                                              DN=>["C=ACME","O=VOMS::Lite","CN=$host"],
                                              CA=>"False",
                                            Bits=>512,
                                  subjectAltName=>["dNSName=$host"],
                                        Lifetime=>86400 } ) };
if (defined $host{Cert} &&  defined $host{Key} && ! defined $host{Errors} ) { ok(1); } else { ok(0); print STDERR "Not Able to create a host certificate\n"; }
eval { VOMS::Lite::PEMHelper::writeCert("$etc/vomscert.pem", $host{'Cert'});  }; if ($@) { ok(0); print STDERR "$@"; } else { ok(1); }
eval { VOMS::Lite::PEMHelper::writeKey("$etc/vomskey.pem", $host{'Key'}, ''); }; if ($@) { ok(0); print STDERR "$@"; } else { ok(1); }

#Make user certificate here
my %user = %{ VOMS::Lite::X509::Create( { Serial=>2,
                                          CACert=>$CA{'Cert'},
                                           CAKey=>$CA{'Key'},
                                              DN=>["C=ACME","O=VOMS::Lite","CN=A Perl User"],
                                              CA=>"False",
                                            Bits=>512,
                                  subjectAltName=>["rfc822Name=root\@$host"],
                                        Lifetime=>86400 } ) };
if (defined $user{Cert} &&  defined $user{Key} && ! defined $user{Errors} ) { ok(1); } else { ok(0); print STDERR "Not Able to create a user certificate\n"; }
eval { VOMS::Lite::PEMHelper::writeCert("$etc/usercert.pem", $user{'Cert'}); }; if ($@) { ok(0); print STDERR "$@"; } else { ok(1); }
eval { VOMS::Lite::PEMHelper::writeKey("$etc/userkey.pem", $user{'Key'}, 'testing'); }; if ($@) { ok(0); print STDERR "$@"; } else { ok(1); }

#Make proxy certificate here
eval "require VOMS::Lite::PROXY"; if ($@) { ok(0); print STDERR "$@"; } else { ok(1); }
my %proxy = %{ VOMS::Lite::PROXY::Create( { Cert=>$user{'Cert'},
                                             Key=>$user{'Key'},
                                            Type=>"Legasy",
                                        Lifetime=>36000 } ) };
if (defined $proxy{ProxyCert} &&  defined $proxy{ProxyKey} && ! defined $proxy{Errors} ) { ok(1); } else { ok(0); print STDERR "Not Able to create a proxy certificate\n"; }
eval { VOMS::Lite::PEMHelper::writeCertKey("$etc/proxy", $proxy{'ProxyCert'}, $proxy{'ProxyKey'}, [ $user{'Cert'} ] ); }; if ($@) { ok(0); print STDERR "$@"; } else { ok(1); }

open (CONF,">$etc/voms.conf") or die "Failed to create $etc/voms.conf";
print CONF <<EOF;
CertDir=$etc/certificates
VOMSCert=$etc/vomscert.pem
VOMSKey=$etc/vomskey.pem
AttribType=Dummy
Lifetime=3600
Server=$host
Code=15000
Port=15000
EOF
close CONF;
chmod 0600, "$etc/voms.conf";

# Test VOMS::Lite
$ENV{'VOMS_CONFIG_FILE'} = "$etc/voms.conf";
eval "use VOMS::Lite"; if ($@) { ok(0); print STDERR "$@";  } else { ok(1); }

my $ref=VOMS::Lite::Issue( [$user{Cert}, $CA{Cert}], "/Dummy" );
my %AC=%$ref;
if (defined $AC{Errors}  ) { ok(0); print STDERR "There were errors producing the AC\n"; } else { ok(1); }
if (defined $AC{AC}      ) { ok(1); } else { ok(0); print STDERR "No AC was produced\n"; }
if (defined $AC{Attribs} && "@{ $AC{Attribs} }" eq "/Dummy/Role=NULL/Capability=NULL" ) { ok(1); } else { ok(0); print STDERR "No Attributes were returned from VOMS::Lite::Issue\n"; }

foreach my $key (keys %AC) {
  if ( ref($AC{$key}) eq "ARRAY" ) {
    my $arrayref=$AC{$key};
    my @array=@$arrayref;
    my $tmp=$key;
    foreach (@array) { printf STDERR "%-15s %s\n", "$tmp:","$_"; $tmp=""; }
  }
}

my $ACpemstr;
eval { $ACpemstr=VOMS::Lite::PEMHelper::encodeAC($AC{AC}); }; if ($@) { ok(0); print STDERR "$@";  } else { ok(1); }
print $ACpemstr;

eval { VOMS::Lite::PEMHelper::writeAC("$etc/AC",$AC{AC}); }; if ($@) { ok(0); print STDERR "$@"; } else { ok(1); }

