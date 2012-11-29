#-----------------------------------------------------------
# ws32_2.pl
# Check to determining tampering of w32_2.dll; was told by malware
# analyst that they were seeing WFP being disabled, and one of the
# copies of ws32_2.dll being modified.  This plugin checks the file
# in the system32 dir against the one in the dllcache directory. 
#
# Change history
#   20120928 - updated to FS format
#	  20100923 - created
#
# References
#   
# 
# copyright 2010-2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package ws2_32;
use strict;

my %config = (hasShortDescr => 1,
							category      => "Malware",
							type          => "File",
							output        => "report",
							class 				=> 0,
              osmask        => 3, #XP/2003
              version       => 20120928);

sub getConfig{return \%config}
my $VERSION = $config{version};
sub getShortDescr {
	return "Check ws2_32\.dll for indications of tampering";	
}

sub pluginmain {
	my $class = shift;
	my $win = WinFile->new();
	my $parent = ::getConfig();
	my $drv = $parent->{drive};
	
	my (@sz,@md5);
	my $count = 0;
	
	::logMsg("ws2_32 v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("ws2_32 v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
	my $file = $drv."Windows\\system32\\ws2_32\.dll";
	::rptMsg("File: ".$file);
	if (-e $file && -f $file) {
#		my $ver = $win->getFileVersionInfo($file);
#		::rptMsg("  FileVersion: ".$ver->{FileVersion});
		$sz[0] = $win->getSize($file);
		$md5[0] = $win->getMD5($file);
		::rptMsg("  MD5        : ".$md5[0]);
		$count++;
	}
	else {
		::rptMsg($file." not found.");
	}
	::rptMsg("");
	my $file = $drv."Windows\\system32\\dllcache\\ws2_32\.dll";
	::rptMsg("File: ".$file);
	if (-e $file && -f $file) {
#		my $ver = $win->getFileVersionInfo($file);
#		::rptMsg("  FileVersion: ".$ver->{FileVersion});
		$sz[1] = $win->getSize($file);
		$md5[1] = $win->getMD5($file);
		::rptMsg("  MD5        : ".$md5[1]);
		$count++;
	}
	else {
		::rptMsg($file." not found.");
	}
	::rptMsg("");
	
	if ($count > 1) {
		if ($md5[0] == $md5[1]) {
			::rptMsg("Both copies of ws2_32\.dll match.");
		}
		else {
			::rptMsg("The copies of ws2_32\.dll do NOT match.");
		}
	}

}

1;