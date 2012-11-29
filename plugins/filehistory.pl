#-----------------------------------------------------------
# filehistory.pl
# Get filehistory settings
#
# Change history
#   20120925 - updated to RS format
#   20120722 - updated %config hash
#   20120620 - updated/modified by H. Carvey
#   20120607 - created by K. Johnson
#
# References
#   This RegRipper plugin was created based on research I have done on 
#   the FileHistory Feature of Windows 8. 
#   http://randomthoughtsofforensics.blogspot.com/
# 
# FileHistoy Plugin copyright 2012 K. Johnson
# Edited by H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package filehistory;
use strict;

my %config = (hive          => "NTUSER\.DAT",
							hivemask      => 0x10,
							type          => "Reg",
							class         => 1,
							output        => "report",
							category      => "User Activity",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 32,  #Windows 8
              version       => 20120925);

sub getConfig{return \%config}
sub getShortDescr {
	return "Gets filehistory settings (Win8)";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
	
	::logMsg("filehistory v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("filehistory v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");

	my $profile = $parent->{userprofile};
	::rptMsg("Profile: ".$profile);
#	my @u = split(/\\/,$profile);
#	my $n = scalar(@u) - 1;
#	my $user = $u[$n];
	$profile .= "\\" unless ($profile =~ m/\\$/);	
	my $ntuser = $profile."NTUSER\.DAT";
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my $key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\FileHistory";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		::rptMsg("");
		my @vals = $key->get_list_of_values();
		
		if (scalar(@vals) > 0) {
			foreach my $v (@vals) {
				
				if ($v->get_name() eq "ProtectedUpToTime") {
					my @t = unpack("VV",$v->get_data());
					my $pft = ::getTime($t[0],$t[1]);
					::rptMsg("  ProtectedUpToTime = ".gmtime($pft)." (UTC)");	
				}
				
				if ($v->get_name() eq "ReassociationPerformed") {
					::rptMsg(sprintf "%-20s 0x%x","ReassociationPerformed",$v->get_data());
				}
				
				if ($v->get_name() eq "RestoreAllowed") {
					::rptMsg(sprintf "%-20s 0x%x","RestoreAllowed",$v->get_data());
				}
				
				if ($v->get_name() eq "SearchRebuildRequired") {
					::rptMsg(sprintf "%-20s 0x%x","SearchRebuildRequired",$v->get_data());
				}
				
				if ($v->get_name() eq "TargetChanged") {
					::rptMsg(sprintf "%-20s 0x%x","TargetChanged",$v->get_data());
				}
			}
		}
		else {
			::rptMsg($key_path." has no values.");
			::rptMsg("File History may not be configured for this user.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

1;