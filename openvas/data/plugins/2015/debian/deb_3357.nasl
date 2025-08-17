# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703357");
  script_cve_id("CVE-2015-6927");
  script_tag(name:"creation_date", value:"2015-09-12 22:00:00 +0000 (Sat, 12 Sep 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3357)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3357");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3357");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vzctl' package(s) announced via the DSA-3357 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that vzctl, a set of control tools for the OpenVZ server virtualisation solution, determined the storage layout of containers based on the presence of an XML file inside the container. An attacker with local root privileges in a simfs-based container could gain control over ploop-based containers. Further information on the prerequisites of such an attack can be found at src.openvz.org.

The oldstable distribution (wheezy) is not affected.

For the stable distribution (jessie), this problem has been fixed in version 4.8-1+deb8u2. During the update existing configurations are automatically updated.

For the testing distribution (stretch), this problem has been fixed in version 4.9.4-2.

For the unstable distribution (sid), this problem has been fixed in version 4.9.4-2.

We recommend that you upgrade your vzctl packages.");

  script_tag(name:"affected", value:"'vzctl' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);