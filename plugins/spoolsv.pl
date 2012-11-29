package spoolsv;
#-----------------------------------------------------------
# spoolsv - plugin to check for tampering of spoolsv.exe
#
# Change history
#   20120822 - updated to new format
#   20111004 - Updated
#   20100923 - created
#
# copyright 2012
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;

my %config = (hasShortDescr => 1,
							shortDescr    => "Check spoolsv\.exe for indications of tampering",
							type          => "File",
							category      => "Malware",
							class         => 0,
							output        => "report",
              osmask        => 3,
              version       => 20120822);

sub getConfig{return \%config}
my $VERSION = $config{version};
sub getShortDescr { return $config{shortDescr};}
my @md5;
my $count = 0;

sub pluginmain {
	my $class = shift;
	my $win = WinFile->new();
	my $parent = ::getConfig();
	my $drv = $parent->{drive};
	my @md5;
	::logMsg("spoolsv v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("spoolsv v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
	my $file = $drv."Windows\\system32\\spoolsv\.exe";
	::rptMsg("File: ".$file);
	if (-e $file && -f $file) {
		$count++;
		$md5[0] = $win->getMD5($file);
		::rptMsg("  MD5        : ".$md5[0]);
	}
	else {
		::rptMsg($file." not found.");
	}
	::rptMsg("");
	my $file = $drv."Windows\\system32\\dllcache\\spoolsv\.exe";
	::rptMsg("File: ".$file);
	if (-e $file && -f $file) {
		$count++;
		$md5[1] = $win->getMD5($file);
		::rptMsg("  MD5        : ".$md5[1]);
	}
	else {
		::rptMsg($file." not found.");
	}
	::rptMsg("");
	if ($count > 1) {
		if ($md5[0] == $md5[1]) {
			::rptMsg("Both copies of spoolsv\.exe match.");
		}
		else {
			::rptMsg("The copies of spoolsv\.exe do NOT match.");
		}
	}
}

1;