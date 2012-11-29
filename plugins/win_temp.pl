package win_temp;
#-----------------------------------------------------------
# win_temp - List files in the %SystemRoot%\Temp dir
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
							shortDescr    => "Check for PE files in %SystemRoot%\\Temp",
							category      => "Malware",
							type          => "File",
              osmask        => 3,
              class         => 0,
              output        => "report",
              version       => 20120822);

sub getConfig{return \%config}
my $VERSION = $config{version};
sub getShortDescr { return $config{shortDescr};}

sub pluginmain {
	my $class = shift;
#	my $win = WinFile->new();
	my $parent = ::getConfig();
	::logMsg("win_temp v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("win_temp v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
	my $dir = $parent->{systemroot}."Temp";
	::rptMsg("Directory: ".$dir);
	my @files;
	
	if (-e $dir && -d $dir) {
		opendir(DIR,$dir);
		my @f = readdir(DIR);
		closedir(DIR);
		
		my @files;
		foreach (@f) {
			push(@files,$_) unless (($_ =~ m/^\.$/) || ($_ =~ m/^\.\.$/));
		}
			
		if (scalar @files > 0) {
			foreach my $f (@files) {
				::rptMsg(" -> ".$f);			
			}
		}
		else {
			::rptMsg($dir." has no files.");
		}
	}
	else {
		::rptMsg($dir." not found.");
	}
}
1;