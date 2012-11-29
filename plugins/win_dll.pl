package win_dll;
#-----------------------------------------------------------
# win_dll - List all DLL files in the %SystemRoot% dir
#
# Change History:
#   20120822 - updated to new format
#   20110323 - created
#
# copyright 2012
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;

my %config = (hasShortDescr => 1,
							shortDescr    => "Check for potential for Explorer\.exe DLL hijacking; ".
							                 "DLLs in Windows dir",
							category      => "Malware",
							type          => "File",
							class         => 0,
							output        => "report",
              osmask        => 3,
              version       => 20120822);

sub getConfig{return \%config}
my $VERSION = $config{version};
sub getShortDescr { return $config{shortDescr};}
sub pluginmain {
	my $class = shift;
	my $win = WinFile->new();
	my $parent = ::getConfig();
	::logMsg("win_dll v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("win_dll v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
	my $dir = $parent->{systemroot};
	if (-e $dir && -d $dir) {
		opendir(DIR,$dir);
		my @dlls = grep(/\.dll$/,readdir(DIR));
		closedir(DIR);
		foreach (@dlls) {
			::rptMsg($_);
		}
	}
	else {
		::rptMsg($dir." not found.");
	}
}
1;