package tasks;
#-----------------------------------------------------------
# tasks - List .job files in %SystemRoot%\Tasks dir
#
# Change History:
#   20120928 - updated to FS format
#   20110323 - created
#
# copyright 2011 Quantum Analytics Research, LLC
#-----------------------------------------------------------
use strict;

my %config = (hasShortDescr => 1,
							shortDescr    => "List \.job files in %SystemRoot%\\Tasks dir",
							category      => "Malware",
							type          => "File",
							output        => "report",
							class         => 0, #system
              osmask        => 3, #for now, XP/2003
              version       => 20120928);

sub getConfig{return \%config}
my $VERSION = $config{version};
sub getShortDescr { return $config{shortDescr};}
sub pluginmain {
	my $class = shift;
	my %parent = ::getConfig();
	::logMsg("tasks v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("tasks v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
	my $dir = $parent{systemroot}."Tasks";
	
	my @files;
	
	if (-e $dir && -d $dir) {
		opendir(DIR,$dir);
		my @files = grep(/\.job$/,readdir(DIR));
		closedir(DIR);
		
		if (scalar @files > 0) {
			foreach my $f (@files) {
				::rptMsg(" ".$f);
			}
		}
		else {
			::rptMsg($dir." has no \.job files.");
		}
		
	}
	else {
		::rptMsg($dir." not found.");
	}
}
1;