package VOMS::Lite::AC;

use 5.004;
use strict;
use VOMS::Lite::ASN1Helper qw(Hex DecToHex ASN1BitStr ASN1Wrap);
use VOMS::Lite::CertKeyHelper qw(digestSign);
use VOMS::Lite::X509;
use VOMS::Lite::KEY;
use Sys::Hostname;
use Regexp::Common qw (URI);

require Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
@ISA = qw(Exporter);

$VERSION = '0.09';

#############################################

sub Create {
  my $inputref = shift;
  my %context  = %{$inputref};
  my @error=();
  my @warning=();
  my $AC;

# Check for values which need to be defined
  if ( ! defined $context{'Cert'} )     { push @error,   "VOMS::Lite::AC: Holder certificate not supplied"; }
  if ( ! defined $context{'VOMSCert'} ) { push @error,   "VOMS::Lite::AC: VOMS certificate not supplied"; }
  if ( ! defined $context{'VOMSKey'} )  { push @error,   "VOMS::Lite::AC: VOMS key not supplied"; }
  if ( ! defined $context{'Lifetime'} ) { push @error,   "VOMS::Lite::AC: VOMS AC Lifetime not supplied"; }
  if ( ! defined $context{'Server'} )   { push @error,   "VOMS::Lite::AC: VOMS Server FQDN not supplied"; }
  if ( ! defined $context{'Port'} )     { push @error,   "VOMS::Lite::AC: VOMS Server Port not supplied"; }
  if ( ! defined $context{'Serial'} )   { push @error,   "VOMS::Lite::AC: VOMS AC Serial not supplied"; }
  if ( ! defined $context{'Code'} )     { push @warning, "VOMS::Lite::AC: Code not supplied, using Port Value"; }
  if ( ! defined $context{'Attribs'} )  { push @error,   "VOMS::Lite::AC: VOMS Attributes not supplied"; }

# Bail if there isn't enough information
  if ( @error > 0 ) { return { Errors => \@error} ; }

# Load input data into local variables
  my $CertInfoRef  = (($context{'Cert'}     =~ /^(\060.*)$/s) ? VOMS::Lite::X509::Examine($&, {X509issuer=>"", X509serial=>"", X509subject=>""}) : undef);
  my $VCertInfoRef = (($context{'VOMSCert'} =~ /^(\060.+)$/s) ? VOMS::Lite::X509::Examine($&, {X509issuer=>"", subjectKeyIdentifier=>"", X509subject=>""}) : undef);
  my $VKeyInfoRef  = (($context{'VOMSKey'}  =~ /^(\060.+)$/s) ?  VOMS::Lite::KEY::Examine($&, {Keymodulus=>"", KeyprivateExponent=>""}) : undef);
  my %CERTINFO;  if ( defined $CertInfoRef )   { %CERTINFO=%$CertInfoRef; }   else { push @error,   "VOMS::Lite::AC: Unable to parse holder certificate."; }
  my %VCERTINFO; if ( defined $VCertInfoRef )  { %VCERTINFO=%$VCertInfoRef; } else { push @error,   "VOMS::Lite::AC: Unable to parse VOMS certificate."; }
  my %VKEYINFO;  if ( defined $VKeyInfoRef )   { %VKEYINFO=%$VKeyInfoRef; }   else { push @error,   "VOMS::Lite::AC: Unable to parse VOMS key."; }
  if ( @error > 0 ) { return { Errors => \@error} ; }

  my $Lifetime     = (($context{'Lifetime'} =~ /^([0-9]+)$/)       ? $& : undef);
  my $Server       = (($context{'Server'}   =~ /^([a-z0-9_.-]+)$/) ? $& : undef);
  my $Port         = (($context{'Port'}     =~ /^([0-9]{1,5})$/ && $context{'Port'} < 65536) ? $& : undef);
  my $Serial       = (($context{'Serial'}   =~ /^([0-9a-f]+)$/)    ? $& : undef);
  my $Code         = (($context{'Code'}     =~ /^([0-9]+)$/)       ? $& : undef);
  my $AttribRef    = $context{'Attribs'};
  my $Broken       = $context{'Broken'};

# Get the attributes from the supplied reference
  my @Attribs=();
  foreach ( @$AttribRef ) {
    my ($cap,$rl);
    if ( /(\/Capability=[\w.-]+)$/ )   { $cap = $1; }
    if ( /(\/Role=[\w.-]+)$cap$/ )     { $rl = $1; }
    if ( /^((?:\/[\w.-]+)+$rl$cap)$/ ) { push @Attribs,$&; }
  }

# Get any targets from the supplied reference
  my @Targets=();
  if (defined $context{'Targets'} && $context{'Targets'} =~ /^ARRAY/ ) {
    foreach ( @{ $context{'Targets'} } ) {
      if (/^($RE{URI})$/) { push @Targets, $1;}
      else { push @error, "VOMS::Lite::AC: At least 1 target was an invalid URI (see eg RFC2396)";}
    }
  }

# Check for errors in local variables
  if ( ! defined $Lifetime )                        { push @error, "VOMS::Lite::AC: Invalid Lifetime"; }
  if ( ! defined $Server )                          { push @error, "VOMS::Lite::AC: Invalid Server"; }
  if ( ! defined $Port )                            { push @error, "VOMS::Lite::AC: Invalid Port"; }
  if ( ! defined $Serial )                          { push @error, "VOMS::Lite::AC: Invalid Serial Number"; }
  if ( ! defined $Code )                            { $Code = $Port; }
  if ( ! defined $CERTINFO{X509issuer} )            { push @error, "VOMS::Lite::AC: Unable to get holder certificate's issuer"; }
  if ( ! defined $CERTINFO{X509serial} )            { push @error, "VOMS::Lite::AC: Unable to get holder certificate's serial"; }
  if ( ! defined $CERTINFO{X509subject} )           { push @error, "VOMS::Lite::AC: Unable to get holder certificate's subject"; }
  if ( ! defined $VCERTINFO{X509issuer} )           { push @error, "VOMS::Lite::AC: Unable to get VOMS certificate's issuer"; }
  if ( ! defined $VCERTINFO{subjectKeyIdentifier} ) { push @error, "VOMS::Lite::AC: Unable to get VOMS certificate's Subject Key Identifier"; }
  if ( ! defined $VCERTINFO{X509subject} )          { push @error, "VOMS::Lite::AC: Unable to get VOMS certificate's subject"; }
  if ( ! defined $VKEYINFO{Keymodulus} )            { push @error, "VOMS::Lite::AC: Unable to get VOMS key's Modulus"; }
  if ( ! defined $VKEYINFO{KeyprivateExponent} )    { push @error, "VOMS::Lite::AC: Unable to get VOMS key's Exponent"; }
  if ( $#Attribs < 0 )                              { push @error, "VOMS::Lite::AC: No Attributes supplied"; }

# Bail if any required variable failed to load 
  if ( @error > 0 ) { return {  Targets => \@Targets, Attribs => \@Attribs, Warnings => \@warning, Errors => \@error }; }

# Pad serial number
  $Serial =~ s/^.(..)*$/0$&/;

# The Identity of this VOMS from first part of first Attribute
  my $Group=(($Attribs[0] =~ /^\/?([^\/]+)/) ? $1 : undef);
  if ( ! defined $Group )    { push @error,   "VOMS::Lite::AC: VOMS Group not defined"; }
  if ( @error > 0 ) { return {  Targets => \@Targets, Attribs => \@Attribs, Warnings => \@warning, Errors => \@error }; }
  my $VOMSURI=$Group."://".$Server.":".$Port;

# Get times Now and Now + N hours
  my @NOW=gmtime(time());
  my @FUT=gmtime(time()+$Lifetime);
  my $NotBeforeDate = sprintf("%04i%02i%02i%02i%02i%02iZ",($NOW[5]+1900),($NOW[4]+1),$NOW[3],$NOW[2],$NOW[1],$NOW[0]);
  my $NotAfterDate  = sprintf("%04i%02i%02i%02i%02i%02iZ",($FUT[5]+1900),($FUT[4]+1),$FUT[3],$FUT[2],$FUT[1],$FUT[0]);

###########################################################
# OK Let's create a VOMS Attribute Certificate!  This consists of:  
# AttCertVersion Holder AttCertIssuer AlgorithmIdentifier CertificateSerialNumber
# AttCertValidityPeriod AttributeSequence UniqueIdentifier Extensions

# Version (=2 (i.e. 01))
  my $AttCertVersion="020101";

# Holder of Attribute.  This this is a sequence containing the holder certificate's issuer DN and serial. 
  my $HolderIssuer            = Hex( ( defined $Broken ) ? $CERTINFO{X509subject}:$CERTINFO{X509issuer} );
  my $HolderSerial            = Hex( $CERTINFO{X509serial} );
  my $HolderInfo              = ASN1Wrap( "30",ASN1Wrap( "a4",$HolderIssuer ) ).$HolderSerial;
  my $Holder                  = ASN1Wrap( "30",ASN1Wrap( "a0",$HolderInfo ) );

# Issuer of Attribute Certificate
  my $AttCertIssuerInfo       = Hex($VCERTINFO{X509subject});
  my $AttCertIssuer           = ASN1Wrap("a0",ASN1Wrap("30",ASN1Wrap("a4",$AttCertIssuerInfo)));

# Signing Algorythm used in this Attribute Certificate
  my $AlgorithmIdentifier     = "300d06092a864886f70d0101040500";

# Serial Number
  my $SN                      = $Serial.DecToHex($Code);
  if ( length($SN) > 80 ) { 
    push @warning, "AC: The size of the serial number is too large, using truncated version.";
    $SN                       = substr($SN,-40);
  }
  my $CertificateSerialNumber = ASN1Wrap("02",$SN);

# Attribute Certificate validity period 
  my $AttCertValidityPeriod   = ASN1Wrap("30",ASN1Wrap("18",Hex($NotBeforeDate)).ASN1Wrap("18",Hex($NotAfterDate)));

# Attributes from Attrib array supplied and VOMS URI (from group, server and port)
  my $VOMSOIDChunck           = "060a2b06010401be45646404";  # OID, encoded-length=10, 1.3.6.1.4.1.8005.100.100.4
  my $VOMSURIChunck           = ASN1Wrap("a0",ASN1Wrap("86",Hex("$VOMSURI")));
  my $VOMSTripleChunck        = "";
  my $VT="";
  foreach (@Attribs) { $VT   .= ASN1Wrap("04",Hex($_)); }   # Concatination of wrapped Attributes
  $VOMSTripleChunck           = ASN1Wrap("30",$VT);
  my $VOMSAttribChunck        = ASN1Wrap("31",ASN1Wrap("30",$VOMSURIChunck.$VOMSTripleChunck));
  my $AttributeSequence       = ASN1Wrap("30",ASN1Wrap("30",$VOMSOIDChunck.$VOMSAttribChunck));

#Unique Identifier
  my $UniqueIdentifier="";   # Optional and we do not specify it here

#Extensions
  #Targets
  my $ACTargets="";
  my $targetInformation="";
  foreach my $uniformResourceIdentifier (@Targets) {
    $ACTargets.=ASN1Wrap("30",ASN1Wrap("a0",ASN1Wrap("a0",ASN1Wrap("86",$uniformResourceIdentifier))));
  }
  if ($ACTargets ne "") { $targetInformation=ASN1Wrap("30","0603551d37". # OID 2.5.29.55
                                                       "0101ff".          # Critical
                                                       ASN1Wrap("04",ASN1Wrap("30",$ACTargets)));}
  #Issuer Certs
  my $IssuerCerts="";
  #NoRevocation
  my $NoRevAvail = "30090603551d3804020500";   # OID 2.5.29.56 + contents=Null
  #Issuer Unique ID
  my $IssuerUniqueID=ASN1Wrap("30","0603551d23".ASN1Wrap("04",ASN1Wrap("30",ASN1Wrap("80",Hex($VCERTINFO{subjectKeyIdentifier})))));
  #Tags
  my $Tag="";

  my $Extensions=ASN1Wrap("30",$targetInformation.$IssuerCerts.$NoRevAvail.$IssuerUniqueID.$Tag);

# Concatinate and wrap into a ToBeSignedAttributeCertificate
  my $UnsignedAC              = ASN1Wrap("30",$AttCertVersion.
                                               $Holder.
                                               $AttCertIssuer.
                                               $AlgorithmIdentifier.
                                               $CertificateSerialNumber.
                                               $AttCertValidityPeriod.
                                               $AttributeSequence.
                                               $UniqueIdentifier.
                                               $Extensions);

###########################################################
# Make MD5 Checksum
  my $BinaryUnsignedAC        = $UnsignedAC;
  $BinaryUnsignedAC          =~ s/(..)/pack('C',hex($&))/ge;

# Make MD5 signature and rsa sign it
  my $RSAsignedDigest         = digestSign("md5WithRSA",$BinaryUnsignedAC,Hex($VKEYINFO{KeyprivateExponent}),Hex($VKEYINFO{Keymodulus}));

  my $ACSignature             = ASN1Wrap("03",ASN1BitStr($RSAsignedDigest)); #(Always n*8 bits for MDnRSA and SHA1RSA)

# Wrap it all up
#  $AC=ASN1Wrap("30",ASN1Wrap("30",ASN1Wrap("30",$UnsignedAC.$AlgorithmIdentifier.$ACSignature)));
  $AC=ASN1Wrap("30",$UnsignedAC.$AlgorithmIdentifier.$ACSignature);
  $AC=~s/(..)/pack('C',hex($&))/ge;

  return { AC => $AC, Targets => \@Targets, Attribs => \@Attribs, Warnings => \@warning };
}

1;
__END__

=head1 NAME

VOMS::Lite::AC - Perl extension for VOMS Attribute certificate creation

=head1 SYNOPSIS

  use VOMS::Lite::AC;
  %AC = %{ VOMS::Lite::AC::Create(%inputref) };
  
=head1 DESCRIPTION

VOMS::Lite::AC is primarily for internal use.

VOMS::Lite::AC::Create takes one argument, a hash containing all the relevant information required to make the 
Attribute Certificate.  
  In the Hash the following scalars should be defined:
  'Cert'     the DER encoding of the holder certificate.
  'VOMSCert' the DER encoding of the VOMS issuing certificate.
  'VOMSKey'  the DER encoding of the VOMS issuing key.
  'Lifetime' the integer lifetime of the credential to be issued in seconds
  'Server'   the FQDN of the VOMS server
  'Port'     the port of the VOMS server (between 0 and 65536) 
  'Serial'   the valus foe the serial number of the credential
  'Code'     optional, the VOMS code (if undefined will use the port and issue a warning)
  'Broken'   optional, define this to make AC issue broken backward compatable gLite 1 VOMS ACs.
  In vector context
  'Attribs'  the reference to the array of VOMS attribute triples
  'Targets'   optional, reference to an array of Target URIs

The return value is a reference to a hash containing the AC as a string in DER format,
a reference to an array of any Target URIs emposed,
a reference to an array of warnings (an AC will still be issued if warnings are present),
a reference to an array of errors (if an error is encountered then no AC will be produced).

=head2 EXPORT

None by default;  

=head1 SEE ALSO

RFC3281 and the VOMS Attribute Specification document from the OGSA Athuz Working Group of the Open Grid Forum http://www.ogf.org.  
Also see gLite from the EGEE.

This module was originally designed for the SHEBANGS project at The University of Manchester.
http://www.rcs.manchester.ac.uk/research/shebangs/

Mailing list, shebangs@listserv.manchester.ac.uk

Mailing list, voms-lite@listserv.manchester.ac.uk

=head1 AUTHOR

Mike Jones <mike.jones@manchester.ac.uk>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006, 2009 by Mike Jones

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.3 or,
at your option, any later version of Perl 5 you may have available.


=cut
