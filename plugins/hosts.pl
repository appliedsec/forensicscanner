package hosts;
#-----------------------------------------------------------
# hosts - check hosts file for signs of tampering; prints out
#   only those lines that are not comments and not blank
#
# Change History:
#   20120816 - updated to latest version of scanner
#   20111004 - Updated
#   20100928 - Created
#
# References:
#   
#
#
# copyright 2012
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;

my %config = (hasShortDescr => 1,
	            shortDescr    => "Check hosts file for indications of tampering",
							category      => "Malware",
							output        => "report",
							class         => 0, # system = 0, user = 1
							type          => "File",
              osmask        => 31,  #XP - Win7; need to test on Win8
              version       => 20120816);

sub getConfig{return \%config}
my $VERSION = $config{version};
sub getShortDescr { return $config{shortDescr};}
sub pluginmain {
	my $class = shift;
#	my $win = WinFile->new();
	my $parent = ::getConfig();
	my $drv = $parent->{drive};
	::logMsg("hosts v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("hosts v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
#	::rptMsg($config{shortDescr});
#	::rptMsg("");
	my $file = $drv."Windows\\system32\\drivers\\etc\\hosts";
	::rptMsg("File: ".$file);
	if (-e $file && -f $file) {
		my %hosts;
		open(FH,"<",$file);
		while(<FH>) {
			chomp;
# skip comment lines or empty lines
			next if ($_ =~ m/^#/ || $_ =~ m/^\s+$/);
			::rptMsg($_);
		}
		close(FH);
	}
	else {
		::rptMsg($file." not found.");
	}
}
1;