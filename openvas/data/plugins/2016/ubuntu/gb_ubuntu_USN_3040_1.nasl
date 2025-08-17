# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842841");
  script_cve_id("CVE-2016-3424", "CVE-2016-3459", "CVE-2016-3477", "CVE-2016-3486", "CVE-2016-3501", "CVE-2016-3518", "CVE-2016-3521", "CVE-2016-3588", "CVE-2016-3614", "CVE-2016-3615", "CVE-2016-5436", "CVE-2016-5437", "CVE-2016-5439", "CVE-2016-5440", "CVE-2016-5441", "CVE-2016-5442", "CVE-2016-5443");
  script_tag(name:"creation_date", value:"2016-08-02 05:25:44 +0000 (Tue, 02 Aug 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Ubuntu: Security Advisory (USN-3040-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3040-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3040-1");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-50.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-31.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-13.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.5, mysql-5.6, mysql-5.7' package(s) announced via the USN-3040-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.5.50 in Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
Ubuntu 15.10 has been updated to MySQL 5.6.31. Ubuntu 16.04 LTS has been
updated to MySQL 5.7.13.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information:
[link moved to references]
[link moved to references]
[link moved to references]
[link moved to references]");

  script_tag(name:"affected", value:"'mysql-5.5, mysql-5.6, mysql-5.7' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
