# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# ------------------------------------------------------------------
# METADATA
# ------------------------------------------------------------------

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130358");
  script_version("2025-08-12T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-12 05:40:06 +0000 (Tue, 12 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Enable the firewalld Service");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.1 Enable the firewalld Service (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.1 Enable the firewalld Service (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.1 Enable the firewalld Service (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.1 Enable the firewalld Service (Recommendation)");

  script_tag(name:"summary", value:"A firewall is an important tool for ensuring network security
as it provides a mandatory access control mechanism between different networks or systems. Firewall
systems can be tailored based on the actual networking requirements. If the firewall service is not
configured in the system, the system may be attacked by external attackers, internal data may be
stolen or tampered with, a large amount of invalid traffic wastes bandwidth, and access to websites
that have security risks or are irrelevant to services may leak information.

It is necessary to install the firewall in the Linux OS connected to the network so that only valid
network traffic is allowed to pass through the system. For example, the firewall allows only
devices with specified IP addresses to access the SSH service. You can customize firewall
configurations to meet specific requirements or security requirements.

Three common firewall service configuration pages are provided in openEuler: firewalld, iptables,
and nftables. The firewalld's underlying layer invokes the iptables or nftables mechanism.

By default, you are advised to enable the firewalld service and disable the iptables and nftables
services.

You are advised to enable only one of the three firewall services. If multiple firewall rules are
improperly set, rule conflicts and protection disorder may occur.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Enable the firewalld Service";

solution = 'Run the following commands to enable the firewalld service and make the configuration
take effect permanently:

# service firewalld start
# systemctl enable firewalld

Run the following commands to disable the iptables and nftables services and make the
configurations take effect permanently:

# service iptables stop
# service nftables stop
# systemctl disable iptables
# systemctl disable nftables';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# service firewalld status 2>&1 |  grep -i active

2. Run the command in the terminal:
# service iptables status 2>&1 |  grep -i active

3. Run the command in the terminal:
# service nftables status 2>&1 |  grep -i active';

expected_value = '1. The output should contain "active (running)"
2. The output should contain "inactive (dead)" or be empty
3. The output should contain "inactive (dead)" or be empty';

# ------------------------------------------------------------------
# CONNECTION CHECK
# ------------------------------------------------------------------

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){

  report_ssh_error(title: title,
                   solution: solution,
                   action: action,
                   expected_value: expected_value,
                   check_type: check_type);
  exit(0);
}

overall_pass = FALSE;
actual_value = "";

# ------------------------------------------------------------------
# CHECK 1 :  Verify that the firewalld service is active
# ------------------------------------------------------------------

step_cmd_check_1 = 'service firewalld status 2>&1 |  grep -i active';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(strstr(step_res_check_1, 'active (running)')){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify that the iptables service is inactive
# ------------------------------------------------------------------

step_cmd_check_2 = 'service iptables status 2>&1 |  grep -i active';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(strstr(step_res_check_2, 'inactive (dead)') || !step_res_check_2){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 3 :  Verify that the nftables service is inactive
# ------------------------------------------------------------------

step_cmd_check_3 = 'service nftables status 2>&1 |  grep -i active';
step_res_check_3 = ssh_cmd(socket:sock, cmd:step_cmd_check_3, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '3. ' + step_res_check_3 + '\n';
check_result_3 = FALSE;

if(strstr(step_res_check_3, 'inactive (dead)') || !step_res_check_3){
  check_result_3 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------
if(check_result_1 && check_result_2 && check_result_3){
  overall_pass = TRUE;
}

if(overall_pass){
  compliant = "yes";
  comment = "All checks passed";
}else{
  compliant = "no";
  comment = "One or more checks failed";
}

# ------------------------------------------------------------------
# REPORT
# ------------------------------------------------------------------

report_audit(action: action,
             actual_value: actual_value,
             expected_value: expected_value,
             is_compliant: compliant,
             solution: solution,
             check_type: check_type,
             title: title,
             comment: comment);

exit(0);