#-----------------------------------------------------------
# winbackup.pl
#
# Change History
#   20120925 - updated to RS format (H. Carvey)
#   20120812 [fpi] % created from winver.pl
#
# References
#
# copyright 2012 M. DeGrazia, arizona4n6@gmail.com
#-----------------------------------------------------------
package winbackup;
use strict;

my %config = (hive          => "Software",
              hivemask      => 0x08,
              type          => "Reg",
              output        => "report",
              class         => 0,
              category      => "System Config",
              osmask        => 16,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20120925);

sub getConfig{return \%config}

sub getShortDescr {
	return "Get Windows Backup Info";
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	my $parent = ::getConfig();
	
	::logMsg("winbackup v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("winbackup v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
		
	my $reg = Parse::Win32Registry->new($parent->{software});
	my $root_key = $reg->get_root_key;

	my $key_path = "Microsoft\\Windows\\CurrentVersion\\WindowsBackup\\ScheduleParams\\TargetDevice";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		::rptMsg("");
	        
    my $name;
		eval {
			$name = $key->get_value("PresentableName")->get_data();
			::rptMsg("  PresentableName = ".$name);
		};
		if ($@) {
#			::rptMsg("PresentableName value not found.");
		}
		
    my $uniquename;
		eval {
			$uniquename = $key->get_value("UniqueName")->get_data();
			::rptMsg("  UniqueName = ".$uniquename);
		};
		if ($@) {
#			::rptMsg("UniqueName value not found.");
		}

                
    my $devlabel;
		eval {
			$devlabel = $key->get_value("Label")->get_data();
			::rptMsg("  Label = ".$devlabel);
		};
		if ($@) {
#			::rptMsg("Label value not found.");
		}
		
    my $vendor;
		eval {
			$vendor = $key->get_value("DeviceVendor")->get_data();
			::rptMsg("  DeviceVendor  = ".$vendor);
		};
		if ($@) {
#			::rptMsg("DeviceVendor value not found.");
		}
		
   	my $deviceproduct;
		eval {
			$deviceproduct = $key->get_value("DeviceProduct")->get_data();
			::rptMsg("  DeviceProduct  = ".$deviceproduct);
		};
		if ($@) {
#			::rptMsg("DeviceVendor value not found.");
		}

    my $deviceversion;
		eval {
			$deviceversion = $key->get_value("DeviceVersion")->get_data();
			::rptMsg("  DeviceVersion  = ".$deviceversion);
		};
		if ($@) {
#			::rptMsg("DeviceVendor value not found.");
		}
		
    my $devserial;
		eval {
			$devserial = $key->get_value("DeviceSerial")->get_data();
			::rptMsg("  DeviceSerial = ".$devserial);
		};
		if ($@) {
#			::rptMsg("DeviceSerial value not found.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
	
#status
  ::rptMsg("");
  my $key_path = "Microsoft\\Windows\\CurrentVersion\\WindowsBackup\\Status";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		::rptMsg("");
		
    my $lastresulttime;
		eval {
			$lastresulttime = $key->get_value("LastResultTime")->get_data();
			my @vals = unpack("VV",$lastresulttime);
			my $lrt = ::getTime($vals[0],$vals[1]);
			::rptMsg("  LastResultTime = ".gmtime($lrt)." (UTC)");
		};
		if ($@) {
#			::rptMsg("LastSuccess value not found.");
		}
		
    my $lastsuccess;
		eval {
			$lastsuccess = $key->get_value("LastSuccess")->get_data();
			my @vals = unpack("VV",$lastsuccess);
			my $ls = ::getTime($vals[0],$vals[1]);
			::rptMsg("  LastSuccess = ".gmtime($ls)." (UTC)");
		};
		if ($@) {
#			::rptMsg("LastSuccess value not found.");
		}
		
    my $lasttarget;
		eval {
			$lasttarget = $key->get_value("LastResultTarget")->get_data();
			::rptMsg("  LastResultTarget = ".$lasttarget);
		};
		if ($@) {
#			::rptMsg("LastResultTarget value not found.");
		}

		my $LRTPrestName;
		eval {
			$LRTPrestName = $key->get_value("LastResultTargetPresentableName")->get_data();
			::rptMsg("  LastResultTargetPresentableName  = ".$LRTPrestName);
		};
		if ($@) {
#			::rptMsg("LastResultTargetPresentableName value not found.");
		}
		
		my $LRTTargetLabel;
		eval {
			$LRTTargetLabel = $key->get_value("LastResultTargetLabel")->get_data();
			::rptMsg("  LastResultTargetLabel = ".$LRTTargetLabel);
		};
		if ($@) {
#			::rptMsg("LastResultTargetLabel value not found.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}
1;