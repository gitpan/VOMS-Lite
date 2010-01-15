package VOMS::Lite::VOMS;

#Use/require here
use VOMS::Lite::ASN1Helper qw(DecToHex Hex ASN1Wrap ASN1Index ASN1OIDtoOID);
use IO::Socket;
use VOMS::Lite::X509;
use VOMS::Lite::CertKeyHelper;
use VOMS::Lite::PEMHelper qw(readCert writeCert writeKey readPrivateKey encodeAC);
use VOMS::Lite::RSAHelper qw(rsaencrypt rsasign);
use Digest::MD5 qw(md5_hex md5);
use Digest::SHA1 qw(sha1_hex sha1);
use Crypt::CBC;

require Exporter;
use vars qw($VERSION $DEBUG @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
@ISA = qw(Exporter);
$VERSION = '0.09';

BEGIN {
  $DEBUG='no';
}

my $maxrecordsize=16384;
sub ContMesg { return sprintf("%08s",DecToHex(length($_[0])/2)); } # returns hex continuation message for hexstring
sub Bin { return pack("H*", $_[0]); }
sub handShake { return $_[0].sprintf("%06s",DecToHex(length($_[1])/2)).$_[1]; }
sub Seq { return sprintf("%016s",DecToHex($_[0])); }
sub recordLayer { 
  my $rsz=$maxrecordsize*2; my $rs;
  my $len=length($_[1]);
  for (my $i=0;($i<$len) and $f=substr($_[1],$i,$rsz);$i+=$rsz) { $rs.=$_[0]."0300".sprintf("%04s",DecToHex(length($f)/2)).$f; } 
  return $rs; 
} 
sub debug {
  return if ( $DEBUG ne "yes" );
  my ($type,$out,$hex) = @_;
  if ( $out =~ /^[\n -~]*$/ and ! defined($hex) ) { $out =~ s/.{1,60}/printf("%-19s %s\n",$type,$&),$type=""/ges; }
  else                            { $out =~ s/(.{1,20})/$a=Hex($1), $a=~s|..|$& |g,printf("%-19s %s\n",$type,$a),$type=""/ges; }
  print $out;
}

#########TODO
# 1. Exporter Get, DEBUG
# 2. Commands to run array of group/role strings

sub Get {
  my %context=%{ $_[0]};
  my @error; my @warning;

  if ( $] < 5.004 ) { push @warning, "VOMS::Lite::VOMS::Get: Perl version is old; random seed is not good"; }

  if ( ! defined $context{'Server'} )   { push @error, "VOMS::Lite::VOMS::Get: Server not Specified"; }
  if ( ! defined $context{'Port'} )     { push @error, "VOMS::Lite::VOMS::Get: Port not Specified"; }
  if ( ! defined $context{'FQANs'} )    { push @error, "VOMS::Lite::VOMS::Get: No FQANs requested"; }
  if ( ! defined $context{'Lifetime'} ) { push @warning, "VOMS::Lite::VOMS::Get: No Lifetime specified, requesting 12 hours";  }

# IO::SOCKET::SSL may optionally use a cert and key on the file system;
  if ( ! defined $context{'Cert'} && ! defined $context{'CertFile'} ) { push @error, "VOMS::Lite::VOMS::Get: Certificate not Specified"; }
  if ( ! defined $context{'Key'} && ! defined $context{'KeyFile'} )   { push @error, "VOMS::Lite::VOMS::Get: Key not Specified"; }
  if ( ! defined $context{'Cert'} && defined $context{'CertFile'} && ! -r $context{'CertFile'} ) { push @error, "VOMS::Lite::VOMS::Get: Certificate file unreadable"; }
  if ( ! defined $context{'Key'} && defined $context{'KeyFile'} && ! -r $context{'KeyFile'} ) { push @error, "VOMS::Lite::VOMS::Get: Key file unreadable"; }

  if (ref( $context{'FQANs'} ) ne 'ARRAY') { push @error,"VOMS::Lite::VOMS::Get: FQANs must be a reference to an array of FQANs."; }
  if ( @error > 0 ) { return { Errors => \@error, Warnings => \@warning }; }

  my $Server       = (($context{'Server'}   =~ /^([a-z0-9_.-]+)$/) ? $& : undef);
  my $Port         = (($context{'Port'}     =~ /^([0-9]{1,5})$/ && $context{'Port'} < 65536) ? $& : 7512);
#  my $lifetime     = ((( defined  $context{'Lifetime'} && $context{'Lifetime'} =~ /^([0-9]+)$/s) ) ? $& : undef);
  my $lifetime     = ((defined  $context{'Lifetime'}) ? ( ($context{'Lifetime'} =~ /^([0-9]+)$/s ) ? $& : undef ) : 43200 );
  my @FQANs        = @{ $context{'FQANs'} };
  foreach (@FQANs) { if (!m|^/[a-zA-Z0-9_.-]+(/[^/]+)*$|) { push @error, "VOMS::Lite::VOMS::Get: \"$_\" is not a valid FQAN."; } }

# Barf if data is not good
  if ( ! defined $Server )         { push @error, "VOMS::Lite::VOMS::Get: Bad VOMS server string"; }
  if ( ! defined $Port )           { push @error, "VOMS::Lite::VOMS::Get: Bad Port"; }
  if ( ! defined $lifetime )       { push @error, "VOMS::Lite::VOMS::Get: Invalid Lifetime $context{'Lifetime'}. Must be a positive integer. e.g. 43200 for 12h"; }

  my @certs; my $key;
  if ( ref($context{'Cert'}) eq "ARRAY" ) { @certs = @{ $context{'Cert'} }; }
  elsif ( defined($context{'Cert'}) and ref($context{'Cert'}) eq "" )   { @certs = ( $context{'Cert'} ); } #might consider a function to seperate concatenated DERs 
  elsif ( defined($context{'Cert'}) )     { push @error, "VOMS::Lite::VOMS::Get: Certs Argument was not a reference to an array nor a scalar"; }
  else { @certs = ( readCert($context{'CertFile'}) );}
  if ( ! @certs ) { push @error, "VOMS::Lite::VOMS::Get: Unable to get any user certs."; }
  foreach my $i (0 .. $#certs) { if ( $certs[$i] !~ /^\x30/s ) { push @error, "VOMS::Lite::VOMS::Get: Supplied certificate (\@context{'Cert'}[$i]) $certs[$i] not in DER format"; } }

  if ( defined $context{'Key'} && $context{'Key'} !~ /^\x30/s ) { push @error, "VOMS::Lite::VOMS::Get: Supplied Key not in DER format"; }
  if ( defined $context{'Key'} ) { $key=$context{'Key'}; }
  else { $key=readPrivateKey($context{'KeyFile'}); }
  if (! defined($key) ) { push @error, "VOMS::Lite::VOMS::Get: Unable to get user key."; }

  my @CAdirs;
  if ( defined $context{'CAdirs'} ) {
    if ( ref($context{'CAdirs'}) eq "ARRAY" ) { @CAdirs = @{ $context{'CAdirs'} }; }
    elsif ( ref($context{'Cert'}) eq "" )   { @CAdirs = split(':',$context{'CAdirs'}); }
    else { push @error, "VOMS::Lite::VOMS::Get: CAdirs Argument was not a reference to an array nor a scalar"; }
  }

  foreach my $i (0 .. $#CAdirs) { if ( ! -d $CAdirs[$i] ) { push @error, "VOMS::Lite::VOMS::Get: Supplied CA directory (\@context{'CAdirs'}[$i]) is not a directory"; } }

  if ( @error > 0 ) { return { Errors => \@error, Warnings => \@warning }; }

#Need CAdirs
#==========================================================
  if ( ! @CAdirs and $ENV{X509_CERT_DIR} ) {
    if ( -d $ENV{X509_CERT_DIR} and $ENV{X509_CERT_DIR} =~ /^(.*)$/) { push @CAdirs,$1; }
    else { return { Errors => ['X509_CERT_DIR defined but it is not a directory'], Warnings => \@warnings }; }
  }
  elsif ( ! @CAdirs ) {
    if ( -d "/etc/grid-security/certificates" ) {
      push @CAdirs, "/etc/grid-security/certificates";
      push @warning,"no CAdir specified Using /etc/grid-security/certificates";
    }
    else { 
     return {   Errors => ['No CAdir found, directly: (\$context{CAdirs}), indirectly: \$ENV{X509_CERT_DIR} or implicitly: /etc/grid-security/certificates'], 
              Warnings => \@warnings }; 
    }
  }

#Load in certificate and key
#  if ( ! @certs ) { @certs = readCert($context{'CertFile'}); }
#  if ( ! defined ($key) )   { $key   = readPrivateKey($context{'KeyFile'}); }
#  if ( ! @certs ) { push @error, "VOMS::Lite::VOMS::Get: Unable to load Certificate from file";}
#  if ( ! defined ($key) )   { push @error, "VOMS::Lite::VOMS::Get: Unable to load Key from file";}

# Get details from Cert and Key
  my %certinfo = %{ VOMS::Lite::X509::Examine( $certs[0], { SubjectDN=>"", IssuerDN=>"" }) };
  my %chain    = %{ VOMS::Lite::CertKeyHelper::buildchain( { trustedCAdirs => \@CAdirs, suppliedcerts => \@certs, } ) };
  my @chain    = @{ $chain{'Certs'} };
  my $UserDN   = $chain{'EndEntityDN'};
  my $UserIDN  = $chain{'EndEntityIssuerDN'};
  my %keyinfo  = %{ VOMS::Lite::KEY::Examine( $key, { Keymodulus=>"",KeyprivateExponent=>"" }) };
  my $Keymod   = Hex($keyinfo{'Keymodulus'});
  my $Keyexp   = Hex($keyinfo{'KeyprivateExponent'});
  my $DN       = $certinfo{'SubjectDN'};
  my $IDN      = $certinfo{'IssuerDN'};

#Open a socket to the server
  my $sock = new IO::Socket::INET( PeerAddr => $Server, PeerPort => $Port, Proto => 'tcp', Type => SOCK_STREAM); 
  if ( ! defined ($sock) ) { return { Errors => ["Unable to establish a connection to $Server:$Port"], Warnings => \@warning }; }
  $sock->autoflush(1);

#######################################
#Construct Initial Components required for SSL 
#Random
  my $hextime               = DecToHex(time);
  my $time                  = Bin($hextime);
  my $rnd = "XXXXXXXXXXXXXXXXXXXXXXXXXXXX"; $rnd =~ s/./chr(int(rand 256))/ge;#not so good on Win32 32000 cycle reported
  my $hexrnd                = Hex($rnd);
  my $hexrandom             = $hextime.$hexrnd;
  my $hexsession            = "00";   #none - new session
  my $hexcypher_vec         = "000a";  #Ciphersuite TLS_RSA_WITH_3DES_EDE_CBC_SHA
  my $hexcypher_suits       = sprintf("%04s",DecToHex(length($hexcypher_vec)/2)).$hexcypher_vec;
  my $hexcompression_vec    = "00"; #CompressionMeth  - Use none no need data minimal + this is a lite implementation
  my $hexcompression        = sprintf("%02s",DecToHex(length($hexcompression_vec)/2)).$hexcompression_vec;
#hello
  my $hexssl_version        = "0300";
  my $hexhandshake_parts    = $hexssl_version.$hexrandom.$hexsession.$hexcypher_suits.$hexcompression;
  my $hexhello              = handShake("01",$hexhandshake_parts);
  my $clienthello           = Bin($hexhello); 
  my $hexhellorecord        = recordLayer("16",$hexhello);

#######################################
#Send Client Hello Record
my $hellorecord           = Bin($hexhellorecord); #Client Hello Record ready to send
my $datacont              = Bin(ContMesg($hexhellorecord)); #Continuation Data for Hello Record message
#send continuation data and client hello record seperately
debug("Sending",$datacont); 
debug("Sending",$hellorecord);
print $sock $datacont;
print $sock $hellorecord;

#######################################
# Listen for ServerHello
my $response              = '';
my $len;
my $cont                  = '';
debug("Reading","4 bytes");
$sock->read($cont,4);
debug("Received",$cont);
if ( $cont =~ /(.)(.)(.)(.)/s ) { $len=(ord($1)*16777216 + ord($2)*65536 + ord($3)*256 + ord($4)); }
debug("Reading","$len bytes");
$sock->read($response,$len);
debug("Received",$response);
my $hexserverhellorecord=Hex($response);
my $records="";
my @serverhello;
while (length($response) > 0) {
  my $lenstr=substr($response,0,5,'');
  my $len;
  if ($lenstr =~ /^\x16\x03\x00(.)(.)/s ) { $len=ord($1)*256+ord($2); }
  else { return { Errors => ["Malformed SSL header from server while waiting for SSL ServerHello messages"], Warnings => \@warning }; }
  push @serverhello,Hex($lenstr.substr($response,0,$len));
  $records.=substr($response,0,$len,'');
}
my $serverhello=$records;

#######################################
# Decode ServerHandshake Messages
my %Hand;
while ($records =~ /^(.)(.)(.)(.)/s) { 
  my $len = (ord($2)*65536)+(ord($3)*256)+ord($4);  # Length of the envelope
  my $id  = ord($1);
  substr($records,0,4,'');  # Strip ID and Length bits
  $Hand{$id} = substr($records,0,$len,'');
  debug("Handshake $id len","$len");
  debug("Handshake $id","$Hand{$id}");
}
#Get the host certificate - 1, Verify VOMS service (not vital) 2, key material for pre-master key exchange later
my $certcont = $Hand{11};
my $lcerts = substr($certcont,0,3,'');
my @HOSTcerts=();
while ( length($certcont)>3 && ($lcert=substr($certcont,0,3,''))) { 
  if ($lcert =~ /(.)(.)(.)/s ) { push @HOSTcerts, substr($certcont,0,(ord($1)*65536)+(ord($2)*256)+ord($3),''); }
}
my %ServerCertInfo= %{ VOMS::Lite::X509::Examine( $HOSTcerts[0], { SubjectDN=>"", IssuerDN=>"", Keymodulus=>"", KeypublicExponent=>"" }) };
my $ServerDN=$ServerCertInfo{'SubjectDN'};
debug("Server DN",$ServerDN);
#Check server certificate matches !!!!! Should probably check subject alt name
if ($ServerDN !~ m#/CN=($Server)(/|$)#) { return { Errors => ["Server Distinguished name mismatch expecting Certificate name containing CN=$Server got $ServerDN"], Warnings => \@warning }; }

#Get ServerHello bits and pieces
my $sHello                  = $Hand{2};
my $sHelloVer               = substr($sHello,0,2,'');
my $sHelloTime              = substr($sHello,0,4,'');
my $sHelloRand              = substr($sHello,0,28,'');
my $sHelloIDlen             = ord(substr($sHello,0,1,''));
my $sHelloSessionID         = substr($sHello,0,$sHelloIDlen,'');
my $sHelloCypherSuite       = substr($sHello,0,2,'');
my $sHelloCompressionMethod = substr($sHello,0,1,'');
debug("Session ID",$sHelloSessionID);
#Get Certificate Request (request for authN)
my $sRequest=$Hand{13};
my $ReqTypesCount=ord(substr($sRequest,0,1,''));
my $RSAOK=0;
my @ReqTypes; for (my $a=0; $a<$ReqTypesCount; $a++) { push @ReqTypes,substr($sRequest,0,1,''); if ($ReqTypes[-1] eq "\x01") {$RSAOK=1;} }
my $ReqDNNamesLen=(ord(substr($sRequest,0,1,''))*256)+ord(substr($sRequest,0,1,''));
my $ReqDistinguishedNames=substr($sRequest,0,$ReqDNNamesLen,'');
my @ReqASN1DN;
while ( length($ReqDistinguishedNames) > 0 ) {
  my $DNLen=(ord(substr($ReqDistinguishedNames,0,1,''))*256)+ord(substr($ReqDistinguishedNames,0,1,''));
  push @ReqASN1DN,substr($ReqDistinguishedNames,0,$DNLen,'');
}
#Get ServerHelloDone
my $sHelloDone=$Hand{14};
#Check for RSA
if ($RSAOK==0) { return { Errors => ["Server does not support RSA AuthN"], Warnings => \@warning }; } 

# 1, Check acceptable DNs for Certificates
my $GotCA=0;
foreach (@ReqASN1DN) {
  my $X509subject=$_;
  my @ASN1SubjectDNIndex=ASN1Index($X509subject);
  shift @ASN1SubjectDNIndex;
  my $SubjectDN="";
  while (@ASN1SubjectDNIndex) {
    my ($CLASS,$CONSTRUCTED,$TAG,$HEADSTART,$HEADLEN,$CHUNKLEN)=(0,0,0,0,0);
    until ($TAG == 6 ) { ($CLASS,$CONSTRUCTED,$TAG,$HEADSTART,$HEADLEN,$CHUNKLEN) = @{shift @ASN1SubjectDNIndex}; }
    my $OID=substr($X509subject,($HEADSTART+$HEADLEN),$CHUNKLEN);
    ($CLASS,$CONSTRUCTED,$TAG,$HEADSTART,$HEADLEN,$CHUNKLEN) = @{shift @ASN1SubjectDNIndex};
    my $Value=substr($X509subject,($HEADSTART+$HEADLEN),$CHUNKLEN);
    $SubjectDN.="/".VOMS::Lite::CertKeyHelper::OIDtoDNattrib(ASN1OIDtoOID($OID))."=$Value";
  }
  if ($UserIDN eq $SubjectDN) { debug("MATCHED CA",$SubjectDN); $GotCA=1; } 
  else                        { debug("        CA:", $SubjectDN); }
}
if ( $GotCA==0 ) { return { Errors => ["VOMS server does not support your CA"], Warnings => \@warning }; }

#########################################################
#Talk to the server again
my $hexcertarray =""; 
foreach $cert (@chain) { $hexcertarray.=sprintf("%06s",DecToHex(length($cert))).Hex($cert);}
my $hexcertobj      = sprintf("%06s",DecToHex(length($hexcertarray)/2)).$hexcertarray;
my $hexcertmesg     = handShake("0b",$hexcertobj);
my $hexcertsmessagerecord=recordLayer("16",$hexcertmesg);
my $certmesg = pack("H*", $hexcertmesg); 
my $infodata = "hexcertsmessagerecord\n".$hexcertsmessagerecord;
##ClientKeyExchange
#PreMasterSecret
my $prernd='X' x 46;
$prernd =~ s/./chr(int(rand 256))/ge;
my $hexprernd=Hex($prernd);
my $hexpremastersecret='0300'.$hexprernd;
#MasterSecret
my $hexmaster_secret='';
foreach my $ABBCCC ("41","4242","434343") {
  my $tobesha1ed     = Bin($ABBCCC.$hexpremastersecret.$hexrandom.Hex($sHelloTime.$sHelloRand));
  my $tobemd5ed      = Bin($hexpremastersecret.Digest::SHA1::sha1_hex($tobesha1ed));
  $hexmaster_secret .= Digest::MD5::md5_hex($tobemd5ed);
}
my $master_secret    = Bin($hexmaster_secret);
#generate a key block
my $key_block='';
foreach my $ABBCCC ("41","4242","434343","44444444","4545454545","464646464646","47474747474747") {
  my $tobesha1ed     = Bin($ABBCCC.$hexmaster_secret.Hex($sHelloTime.$sHelloRand).$hexrandom);
  my $tobemd5ed      = $master_secret.Digest::SHA1::sha1($tobesha1ed);
  $key_block        .= Digest::MD5::md5($tobemd5ed);
}
#Make Client Key Exchange
my $hexEncPMSecret   = rsaencrypt($hexpremastersecret,Hex($ServerCertInfo{'KeypublicExponent'}),Hex($ServerCertInfo{'Keymodulus'}));
my $hexClientKeyExchange  = handShake("10",$hexEncPMSecret);    #### USE ME FOR CertificateVarify
my $hexClientKeyExchangeMessageRecord = recordLayer("16",$hexClientKeyExchange);
my $ClientKeyExchangeMessage = pack("H*", $hexClientKeyExchange); #### ClientCertificate for handshakemessages needs to be without record layer
#CertificateVerify
my $Hmsgs     = $clienthello.$serverhello.$certmesg.$ClientKeyExchangeMessage;
my $pad1md5   = "\x36" x 48; 
my $pad2md5   = "\x5c" x 48; 
my $pad1sha   = "\x36" x 40; 
my $pad2sha   = "\x5c" x 40;
my $verifymac = md5_hex($master_secret.$pad2md5.md5($Hmsgs.$master_secret.$pad1md5)).
                sha1_hex($master_secret.$pad2sha.sha1($Hmsgs.$master_secret.$pad1sha));

my $hexsignedcertificateverify        = rsasign($verifymac,$Keyexp,$Keymod);
my $hexwrappedsignedcertificateverify = sprintf("%04s",DecToHex(length($hexsignedcertificateverify)/2)).$hexsignedcertificateverify;
my $hexcertificateverify              = handShake('0f',$hexwrappedsignedcertificateverify);
my $certificateverify                 = Bin($hexcertificateverify);
my $hex_ssl_certificateverifyrecord   = recordLayer("16",$hexcertificateverify);

## Switch to Encrypted Session -- change_cipher_spec message
#Select algorythm for key exchange -- Must be RSA
my $hexkeyselection="140300000101";

# Switch to tripple des (the only one I support) and send finished message
my $sender              = "CLNT"; #SRVR for server
my $handshakemessages   = $clienthello.$serverhello.$certmesg.$ClientKeyExchangeMessage.$certificateverify; 
my $unencryptedfinished = md5_hex ($master_secret.$pad2md5. md5($handshakemessages.$sender.$master_secret.$pad1md5)).
                          sha1_hex($master_secret.$pad2sha.sha1($handshakemessages.$sender.$master_secret.$pad1sha));

my $unechexfinished=handShake("14",$unencryptedfinished);

#Partition key block for DES+SHA1
my $ClientWriteMACSecret              = substr($key_block,0,20,'');
my $ServerWriteMACSecret              = substr($key_block,0,20,'');
my $ClientWriteKey                    = substr($key_block,0,24,'');
my $ServerWriteKey                    = substr($key_block,0,24,'');
my $ClientWriteIV                     = substr($key_block,0,8,'');
my $ServerWriteIV                     = substr($key_block,0,8,'');

#Set up the Client and Server DES3-EDE sessions
my $Ccipher = Crypt::CBC->new( -literal_key => 1, -padding => 'null', -key => $ClientWriteKey,  -iv => $ClientWriteIV, -header => 'none', -cipher => 'DES_EDE3' );
my $Scipher = Crypt::CBC->new( -literal_key => 1, -padding => 'null', -key => $ServerWriteKey,  -iv => $ServerWriteIV, -header => 'none', -cipher => 'DES_EDE3' );
my $Cseq=0;
my $Sseq=0;

my $hex_finishedrecord = &Encrypt(Bin(recordLayer("16",$unechexfinished)),$ClientWriteMACSecret,$pad1sha,$pad2sha,$Cseq,$Ccipher);
my $hex_finished       = $hex_finishedrecord;
$hex_finished         =~ s/^..........//s;
my $finished           = Bin($hex_finished);

#############################################################################
#Send Records
my $hex_senddata = $hexcertsmessagerecord.$hexClientKeyExchangeMessageRecord.$hex_ssl_certificateverifyrecord.$hexkeyselection.$hex_finishedrecord;
my $senddata     = Bin($hex_senddata);
   $datacont     = Bin(ContMesg($hex_senddata)); #Continuation Data for Hello Record message
my %Messages;
my @order=('hexhellorecord');
my $i=1; foreach (@serverhello) { push @order,"serverHello$i"; $Messages{"serverHello$i"}=$_; $i++; }
push @order,('hexcertsmessagerecord','hexClientKeyExchangeMessageRecord','hex_ssl_certificateverifyrecord','hexkeyselection','hex_finishedrecord');

$Messages{hexhellorecord}                    = $hexhellorecord;
$Messages{hexserverhellorecord}              = $hexserverhellorecord;
$Messages{hexcertsmessagerecord}             = $hexcertsmessagerecord;
$Messages{hexClientKeyExchangeMessageRecord} = $hexClientKeyExchangeMessageRecord;
$Messages{hex_ssl_certificateverifyrecord}   = $hex_ssl_certificateverifyrecord;
$Messages{hexkeyselection}                   = $hexkeyselection;
$Messages{hex_finishedrecord}                = $hex_finishedrecord;

foreach (@order) {my $hex_value=substr($Messages{$_},10); $hex_value =~ s/(..)/$1 /g; $hex_value =~ s/(.{47})./$1\n/g;}
debug("Sending",$datacont);
debug("Sending",$senddata);
print $sock $datacont; print $sock $senddata;

#############################################################################
#Receive Response
debug("Read","4 bytes");
$sock->read($cont,4);
debug("Received",$cont);
if ( $cont =~ /(.)(.)(.)(.)/ ) {  $len2=(ord($1)*256*65536 + ord($2)*65536 + ord($3)*256 + ord($4)); }
$sock->read($response,$len2);
debug("Read","$len2 bytes");
debug("Received",$response);
if ( $response =~ /^\x14\x03\x00\x00\x01\x01/ ) {  $response =~ s/......//; } #Change Cypher Spec -- what we expect
else { return { Errors => ["Error: Expecting SSL Change Cypher Spec Message, got something else. "], Warnings => \@warning }; }
my $serverfinishedhex=Hex(&Decrypt($response,$ServerWriteMACSecret,$pad1sha,$pad2sha,$Sseq,$Scipher));
####### Check response from server is a valid finished message
   $sender="SRVR"; #SRVR for server
   $handshakemessages = $clienthello.$serverhello.$certmesg.$ClientKeyExchangeMessage.$certificateverify.Bin($unechexfinished);
   $unencryptedfinished = md5_hex ($master_secret.$pad2md5. md5($handshakemessages.$sender.$master_secret.$pad1md5)).
                          sha1_hex($master_secret.$pad2sha.sha1($handshakemessages.$sender.$master_secret.$pad1sha));
my $unencryptedfinishedmsg=handShake("14",$unencryptedfinished);
if ($unencryptedfinishedmsg ne $serverfinishedhex) { return { Errors => ["Failed to decrypt server Response"], Warnings => \@warning }; }

####### Send no delegation byte
my $msg='0';
my $emesg        = &Encrypt(Bin(recordLayer("17",Hex($msg))),$ClientWriteMACSecret,$pad1sha,$pad2sha,$Cseq,$Ccipher);
   $senddata     = Bin($emesg);
   $datacont     = Bin(ContMesg($emesg)); #Continuation Data for Hello Record message
debug("Sending",$datacont);
debug("Sending",$senddata);
print $sock $datacont; print $sock $senddata;

####### Send request
#<xml version="1.0" encoding = "US-ASCII"?>
#  <voms>
#    <command>COMMAND</command>+
#    <order>ORDER</order>?
#    <targets>TARGETS</targets>?
#    <lifetime>N</lifetime>?
#    <base64>B</base64>?
#    <version>V</version>?
#  </voms>
# COMMAND:  G/vo.name(/subgroup)* {All relevant} | Rrolename {All relevant} | B/vo.name(/subgroup)*:rolename | A {All} | M {List} | /vo.name(/subgroup)*/Role=rolename
#  my $msg='<?xml version="1.0" encoding = "US-ASCII"?><voms><command>G/ngs.ac.uk/ops</command><base64>1</base64><version>4</version><lifetime>43200</lifetime></voms>';
#  my $msg='<?xml version="1.0" encoding = "US-ASCII"?><voms><command>ROperations</command><base64>1</base64><version>4</version><lifetime>43200</lifetime></voms>';

  my $cmds = "";
  foreach (@FQANs) { 
    s|/Capability=[^/]+||; 
    if ( m|^(.*?)/Role=([^/]+)$| ) {$cmds .= "<command>B$1:$2</command>";}
    else { $cmds .= "<command>G$_</command>"; }
  }
     $msg='<?xml version="1.0" encoding = "US-ASCII"?><voms>'.$cmds.'<base64>1</base64><version>4</version><lifetime>'.$lifetime.'</lifetime></voms>';
     $emesg         = &Encrypt(Bin(recordLayer("17",Hex($msg))),$ClientWriteMACSecret,$pad1sha,$pad2sha,$Cseq,$Ccipher);
  my $senddata2     = Bin($emesg);
  my $datacont2     = Bin(ContMesg($emesg)); #Continuation Data for Hello Record message
  print $sock $datacont2; print $sock $senddata2;
  $sock->read($cont,4);
  if ( $cont =~ /(.)(.)(.)(.)/s ) {  $len2=(ord($1)*256*65536 + ord($2)*65536 + ord($3)*256 + ord($4)); }
  else { return { Errors => ["Expecting to read 4 bytes, to wrap SSL encrypted application data"], Warnings => \@warning}; }
  $sock->read($response,$len2);
  debug("Read","$len2 bytes");
  debug("Received",$response);
  if ( $response !~ /^\x17/ ) { return { Errors => ["Expecting Encrypted Application Data, got something else"], Warnings => \@warning }; }
  my $apdata=&Decrypt($response,$ServerWriteMACSecret,$pad1sha,$pad2sha,$Sseq,$Scipher);
  my ($ac) = $apdata =~ /^.*<ac>([^<]*)<\/ac>.*$/;
  $apdata =~ s|<error><item><number>[0-9]{4,}</number><message>([^<]*)</message></item></error>|push(@error,"Error from VOMS Server: \"$1\"")|ge;
  $apdata =~ s|<error><item><number>[0-9]{1,3}</number><message>([^<]*)</message></item></error>|push(@warning,"Warning from VOMS Server: \"$1\"")|ge;
  if ( @error > 0 ) { return { Errors => \@error, Warnings => \@warning }; }
#  my $vomsac=ASN1Wrap("30",ASN1Wrap("30",Hex(Decode($ac))));
  my $vomsac=Hex(Decode($ac));
  $vomsac=~ s/(..)/pack('C',hex($&))/ge;
  close($sock); 
  return { AC=>encodeAC($vomsac), Warnings => \@warning };
}####Endof sub Get

sub Encode{ return undef;}
sub Decode {
  my $str="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789[]";
  my ($data)=@_;
  my $padlen = (length($data) % 4); ($padlen==3) and $padlen=1;
  my $pad="a" x $padlen; $data.= $pad; #insert pad ourselves (a == \0)
  $data=~s#(.)(.)(.)(.)#chr(((index($str,$1)<<2)&252)+((index($str,$2)>>4)&3)).chr(((index($str,$2)<<4)&240)+((index($str,$3)>>2)&15)).chr(((index($str,$3)<<6)&192)+((index($str,$4))&63))#ge;
  $data=~s/..$//s if ($pad eq "aa");
  $data=~s/.$//s if ($pad eq "a");
  return $data;
}

sub Encrypt { #this routine modifies $_[4,5] Encrypt($rec,$ClientWriteMACSecret,$pad1sha,$pad2sha,$Cseq,$Ccipher)
  my ($rec,$ClientWriteMACSecret,$pad1sha,$pad2sha)=@_;
  debug("Encrypting",length($rec)." Bytes"); debug("MAC Secret",$ClientWriteMACSecret); debug("Sequence",$_[4]);
  my $type=substr($rec,0,1,'');      # First Byte is the Record Type 
  my $version=substr($rec,0,2,'');   # Next 2 bytes are SSL Version
  my $len=substr($rec,0,2,'');       # Length of the unencrypted Record
  my $seq=Bin(Seq($_[4]++)); #update this out of scope
  my $mac=sha1($ClientWriteMACSecret.$pad2sha.sha1($ClientWriteMACSecret.$pad1sha.$seq.$type.$len.$rec)); 
  my $data=$rec.$mac;  
#enc
  my $padnum=7-(length($data)%8);       ###Argh I hate padding: SSL should cope with 080808080808080808 (== 00) 
#  my $padnum=8-((length($data)+1)%8);     # How much padding is required to bring data up to blocksize
  my $pad=chr($padnum) x ($padnum+1) ;     # paddingValue x number . paddingNumber 0101, 020202, 03030303, ...
  debug("IV",$_[5]->get_initialization_vector(),1); debug("MAC",$mac,1); debug("Data",$rec); debug("Padding",$pad,1);
  my $edata=$_[5]->encrypt($data.$pad); # Encrypt data
  debug("Encrypted data",$edata,1);
  $_[5]->set_initialization_vector(substr($edata,-8,8));  #make ready for next enc.
  return recordLayer(Hex($type),Hex($edata));
}

sub Decrypt { #this routine modifies Decrypt($rec,$ServerWriteMACSecret,$pad1sha,$pad2sha,$Sseq,$Scipher) 
  my ($rec,$ServerWriteMACSecret,$pad1sha,$pad2sha)=@_;
#unpack
  debug("Decrypting",length($rec)." bytes"); debug("Encrypted data",$rec,1); debug("MAC Secret",$ServerWriteMACSecret,1); debug("Sequence",$_[4]);
  my $type=substr($rec,0,1,'');
  my $version=substr($rec,0,2,'');
  my $recordlength=substr($rec,0,2,'');
#decrypt
  my $data=$_[5]->decrypt($rec);
#Update
  my $iv=substr($rec,-8,8);
  $_[5]->set_initialization_vector($iv);
#unpad -- ought to be this but have seen examples otherwise...
#... 0707070707070707, 06060606060606, 050505050505, 0404040404, 03030303, 020202, 0101 -- SSL
# 01, 0202, 030303,... -- (PKCS#5, rfc2898)
# openssl has option for random padding / no padding - have seen VOMS server use both :-S
# spec says we can have up to 255 bytes of padding if these are random we'd have to assume padding is always present
# our hands are tied because these are not selfconsistant -- so:
# If padlen byte is 0x01 - 0x08 treat as random/SSL padding, otherwise assume SSL padding and rely upon xml message always ending in '>' i.e. 0x3e and not 0x01-0x08  
  my $padchar=substr($data,-1,1,'');
  my $padlen=ord($padchar);
  my $pad;
  if ( ( $padlen <= 8 && $padlen > 0 ) or ( $padlen > 8 && $data =~ /${padchar}{$padlen}$/s ) ) { 
    $pad=substr($data,(0-$padlen),$padlen,''); 
    debug("Depadded","$padlen (+1) bytes"); debug("Padding",$pad,1);
  }
  else { $data.=$padchar; }
#get mac
  my $mac=substr($data,-20,20,'');
#verify
  my $len=Bin(sprintf("%04s",DecToHex(length($data))));
  my $seq=Bin(Seq($_[4]++));
  my $calcmac=sha1($ServerWriteMACSecret.$pad2sha.sha1($ServerWriteMACSecret.$pad1sha.$seq.$type.$len.$data));
  debug("IV",$iv); debug("MAC expected",$mac,1); debug("MAC derived",$calcmac,1); debug("Data",$data);
  return ($calcmac eq $mac)?$data:undef;
}


1;

__END__

=head1 NAME

VOMS::Lite::VOMS - Perl extension for gLite VOMS server interaction

=head1 SYNOPSIS

  use VOMS::Lite::VOMS;

  $ref = VOMS::Lite::VOMS::Get( { Server => "voms.ngs.ac.uk", 
                                    Port => 15010, 
                                   FQANs => [ "ngs.ac.uk", "ngs.ac.uk/Role=Operations" ],
                                Lifetime => 86400,
                                  CAdirs => "/path/to/CA/certificates",
                                    Cert => [ $DERCert, 
                                              $DERCertSigner, 
                                              $DERCertSignerSigner, ... ], 
                                     Key => $DERKey } );

  $AC       = ${ $ref }{'ac'};             # Contains PEM Encoded Attribute Certificate
  @Errors   = @{ ${ $ref }{'Errors'} };    # An error if encountered will stop the processing
  @Warnings = @{ ${ $ref }{'Warnings'} };  # A warning is not fatal and if no error occurs ${ $ref }{'ac'} will be set

=head1 DESCRIPTION

  Lightweight library to obtain a VOMS attribute certificate from a VOMS server (NOT the VOMS-Admin-Server).

  Input parameters:
    Server      Scalar: Fully Quallified Server Name (It's certificate commonName will be checked aganist this)
    Port        Scalar: The port where the vomsd for this VO is running 
                usually something like 15 thousand and something
    FQANs       Reference to an array: Fully Qualified Attribute Names
    Lifetime    Scalar: Number of seconds to ask the VOMS server to issue the AC for
    CAdirs      Scalar: ':' delimited paths to CA certificates/signers
           -or- Reference to array of paths to CA certificates/signers
    Cert        Scalar: DER formatted certificate/proxy certificate
           -or- Reference to array: DER formatted certificates/proxy certificates
    Key         Scalar: DER formatted Private Key

    CertFile and KeyFile may be specified instead of Cert and Key 
    in which case these must be PEM formatted.

  Returns a reference to a hash containing
    ac          Scalar: PEM encoded Attribute certificate
    Warnings    Reference to an array: warnings encountered
    Errors      Reference to an array: Errors encountered

  For deep Debugging set
    $VOMS::Lite::VOMS::DEBUG='yes';

=head2 EXPORT

None.

=head1 Also See

https://twiki.cnaf.infn.it/cgi-bin/twiki/view/VOMS/VOMSProtocol
http://glite.cvs.cern.ch/cgi-bin/glite.cgi/org.glite.security.voms

RFC3281 and the VOMS Attribute Specification document from the OGSA Athuz Workin
g Group of the Open Grid Forum http://www.ogf.org.
Also see gLite from the EGEE.

This module was originally designed for the JISC funded SARoNGS project at developed at 
The University of Manchester.
http://www.rcs.manchester.ac.uk/projects/shebangs/


=head1 AUTHOR

Mike Jones <mike.jones@manchester.ac.uk>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Mike Jones

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.3 or,
at your option, any later version of Perl 5 you may have available.


=cut
