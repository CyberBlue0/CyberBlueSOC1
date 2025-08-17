# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843628");
  script_cve_id("CVE-2016-10208", "CVE-2017-11472", "CVE-2017-11473", "CVE-2017-14991", "CVE-2017-15649", "CVE-2017-16526", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16531", "CVE-2017-16532", "CVE-2017-16533", "CVE-2017-16535", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16538", "CVE-2017-16643", "CVE-2017-16644", "CVE-2017-16645", "CVE-2017-16650", "CVE-2017-16911", "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-16914", "CVE-2017-17558", "CVE-2017-18255", "CVE-2017-18270", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-2671", "CVE-2017-5549", "CVE-2017-5897", "CVE-2017-6345", "CVE-2017-6348", "CVE-2017-7518", "CVE-2017-7645", "CVE-2017-8831", "CVE-2017-9984", "CVE-2017-9985", "CVE-2018-1000204", "CVE-2018-10021", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-10323", "CVE-2018-10675", "CVE-2018-10877", "CVE-2018-10881", "CVE-2018-1092", "CVE-2018-1093", "CVE-2018-10940", "CVE-2018-12233", "CVE-2018-13094", "CVE-2018-13405", "CVE-2018-13406");
  script_tag(name:"creation_date", value:"2018-08-25 04:48:47 +0000 (Sat, 25 Aug 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-30 21:33:00 +0000 (Fri, 30 Nov 2018)");

  script_name("Ubuntu: Security Advisory (USN-3754-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3754-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3754-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta' package(s) announced via the USN-3754-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ralf Spenneberg discovered that the ext4 implementation in the Linux kernel
did not properly validate meta block groups. An attacker with physical
access could use this to specially craft an ext4 image that causes a denial
of service (system crash). (CVE-2016-10208)

It was discovered that an information disclosure vulnerability existed in
the ACPI implementation of the Linux kernel. A local attacker could use
this to expose sensitive information (kernel memory addresses).
(CVE-2017-11472)

It was discovered that a buffer overflow existed in the ACPI table parsing
implementation in the Linux kernel. A local attacker could use this to
construct a malicious ACPI table that, when loaded, caused a denial of
service (system crash) or possibly execute arbitrary code.
(CVE-2017-11473)

It was discovered that the generic SCSI driver in the Linux kernel did not
properly initialize data returned to user space in some situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2017-14991)

It was discovered that a race condition existed in the packet fanout
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-15649)

Andrey Konovalov discovered that the Ultra Wide Band driver in the Linux
kernel did not properly check for an error condition. A physically
proximate attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2017-16526)

Andrey Konovalov discovered that the ALSA subsystem in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-16527)

Andrey Konovalov discovered that the ALSA subsystem in the Linux kernel did
not properly validate USB audio buffer descriptors. A physically proximate
attacker could use this cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-16529)

Andrey Konovalov discovered that the USB subsystem in the Linux kernel did
not properly validate USB interface association descriptors. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2017-16531)

Andrey Konovalov discovered that the usbtest device driver in the Linux
kernel did not properly validate endpoint metadata. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2017-16532)

Andrey Konovalov discovered that the USB subsystem in the Linux kernel did
not properly validate USB HID descriptors. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2017-16533)

Andrey Konovalov discovered that the USB subsystem in the Linux kernel did
not properly validate USB BOS metadata. A physically proximate attacker
could use this ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-meta' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
