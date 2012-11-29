package ntshrui;
#-----------------------------------------------------------
# ntshrui - check for ntshrui.dll in the %SystemRoot% dir
#
# Change History:
#   20120816 - updated
#   20110323 -  created
#
# References:
#  
#
# TODO: 
#   -Add ability to read/parse PE header via ReadPE.pm
#
# copyright 2012 
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;

my %config = (hasShortDescr => 1,
							shortDescr    => "Check for Explorer DLL hijacking via ntshrui\.dll",
							category      => "Malware",
							class         => 0, # system = 0, user = 1
							output        => "report",
							type          => "File",
              osmask        => 31,  #XP - Win7
              version       => 20120816);

sub getConfig{return \%config}
my $VERSION = $config{version};
sub getShortDescr {
	return "Checks for ntshrui\.dll in the Windows directory (DLL Search Hijacking)";	
}

sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
	::logMsg("ntshrui v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("ntshrui v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
	my $win = WinFile->new();
	my $file = $parent->{drive}."Windows\\ntshrui\.dll";
	if (-e $file && -f $file) {
		::rptMsg($file);
		::rptMsg("  MD5        : ".$win->getMD5($file));
	}
	else {
		::rptMsg($file." not found.");
	}
}
1;