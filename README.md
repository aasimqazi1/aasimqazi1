=~=~=~=~=~=~=~=~=~=~=~= PuTTY log 2022.05.10 14:34:32 =~=~=~=~=~=~=~=~=~=~=~=
cat ansible.cfg
# config file for ansible -- https://ansible.com/
# ===============================================

# nearly all parameters can be overridden in ansible-playbook
# or with command line flags. ansible will read ANSIBLE_CONFIG,
# ansible.cfg in the current working directory, .ansible.cfg in
# the home directory or /etc/ansible/ansible.cfg, whichever it
# finds first

[defaults]

# some basic default values...

#inventory      = /etc/ansible/hosts
#library        = /usr/share/my_modules/
#module_utils   = /usr/share/my_module_utils/
#remote_tmp     = ~/.ansible/tmp
#local_tmp      = ~/.ansible/tmp
#forks          = 5
#poll_interval  = 15
#sudo_user      = root
#ask_sudo_pass = True
#ask_pass      = True
#transport      = smart
#remote_port    = 22
#module_lang    = C
#module_set_locale = False
vault_password_file = /u01/.passwd 
host_key_checking = False
# plays will gather facts by default, which contain information about
# the remote system.
#
# smart - gather by default, but don't regather if already gathered
# implicit - gather by default, turn off with gather_facts: False
# explicit - do not gather by default, must say gather_facts: True
#gathering = implicit

# This only affects the gathering done by a play's gather_facts directive,
# by default gathering retrieves all facts subsets
# all - gather all subsets
# network - gather min and network facts
# hardware - gather hardware facts (longest facts to retrieve)
# virtual - gather min and virtual facts
# facter - import facts from facter
# ohai - import facts from ohai
# You can combine them using comma (ex: network,virtual)
# You can negate them using ! (ex: !hardware,!facter,!ohai)
# A minimal set of facts is always gathered.
#gather_subset = all

# some hardware related facts are collected
# with a maximum timeout of 10 seconds. This
# option lets you increase or decrease that
# timeout to something more suitable for the
# environment. 
# gather_timeout = 10

# additional paths to search for roles in, colon separated
#roles_path    = /etc/ansible/roles

# uncomment this to disable SSH key host checking
#host_key_checking = False

# change the default callback, you can only have one 'stdout' type  enabled at a time.
#stdout_callback = skippy


## Ansible ships with some plugins that require whitelisting,
## this is done to avoid running all of a type by default.
## These setting lists those that you want enabled for your system.
## Custom plugins should not need this unless plugin author specifies it.

# enable callback plugins, they can output to stdout but cannot be 'stdout' type.
#callback_whitelist = timer, mail

# Determine whether includes in tasks and handlers are "static" by
# default. As of 2.0, includes are dynamic by default. Setting these
# values to True will make includes behave more like they did in the
# 1.x versions.
#task_includes_static = True
#handler_includes_static = True

# Controls if a missing handler for a notification event is an error or a warning
#error_on_missing_handler = True

# change this for alternative sudo implementations
#sudo_exe = sudo

# What flags to pass to sudo
# WARNING: leaving out the defaults might create unexpected behaviours
#sudo_flags = -H -S -n

# SSH timeout
#timeout = 10

# default user to use for playbooks if user is not specified
# (/usr/bin/ansible will use current user as default)
#remote_user = root

# logging is off by default unless this path is defined
# if so defined, consider logrotate
#log_path = /var/log/ansible.log

# default module name for /usr/bin/ansible
#module_name = command

# use this shell for commands executed under sudo
# you may need to change this to bin/bash in rare instances
# if sudo is constrained
#executable = /bin/sh

# if inventory variables overlap, does the higher precedence one win
# or are hash values merged together?  The default is 'replace' but
# this can also be set to 'merge'.
#hash_behaviour = replace

# by default, variables from roles will be visible in the global variable
# scope. To prevent this, the following option can be enabled, and only
# tasks and handlers within the role will see the variables there
#private_role_vars = yes

# list any Jinja2 extensions to enable here:
#jinja2_extensions = jinja2.ext.do,jinja2.ext.i18n

# if set, always use this private key file for authentication, same as
# if passing --private-key to ansible or ansible-playbook
#private_key_file = /path/to/file

# If set, configures the path to the Vault password file as an alternative to
# specifying --vault-password-file on the command line.
#vault_password_file = /path/to/vault_password_file

# format of string {{ ansible_managed }} available within Jinja2
# templates indicates to users editing templates files will be replaced.
# replacing {file}, {host} and {uid} and strftime codes with proper values.
#ansible_managed = Ansible managed: {file} modified on %Y-%m-%d %H:%M:%S by {uid} on {host}
# {file}, {host}, {uid}, and the timestamp can all interfere with idempotence
# in some situations so the default is a static string:
#ansible_managed = Ansible managed

# by default, ansible-playbook will display "Skipping [host]" if it determines a task
# should not be run on a host.  Set this to "False" if you don't want to see these "Skipping"
# messages. NOTE: the task header will still be shown regardless of whether or not the
# task is skipped.
#display_skipped_hosts = True

# by default, if a task in a playbook does not include a name: field then
# ansible-playbook will construct a header that includes the task's action but
# not the task's args.  This is a security feature because ansible cannot know
# if the *module* considers an argument to be no_log at the time that the
# header is printed.  If your environment doesn't have a problem securing
# stdout from ansible-playbook (or you have manually specified no_log in your
# playbook on all of the tasks where you have secret information) then you can
# safely set this to True to get more informative messages.
#display_args_to_stdout = False

# by default (as of 1.3), Ansible will raise errors when attempting to dereference
# Jinja2 variables that are not set in templates or action lines. Uncomment this line
# to revert the behavior to pre-1.3.
#error_on_undefined_vars = False

# by default (as of 1.6), Ansible may display warnings based on the configuration of the
# system running ansible itself. This may include warnings about 3rd party packages or
# other conditions that should be resolved if possible.
# to disable these warnings, set the following value to False:
#system_warnings = True

# by default (as of 1.4), Ansible may display deprecation warnings for language
# features that should no longer be used and will be removed in future versions.
# to disable these warnings, set the following value to False:
#deprecation_warnings = True

# (as of 1.8), Ansible can optionally warn when usage of the shell and
# command module appear to be simplified by using a default Ansible module
# instead.  These warnings can be silenced by adjusting the following
# setting or adding warn=yes or warn=no to the end of the command line
# parameter string.  This will for example suggest using the git module
# instead of shelling out to the git command.
# command_warnings = False


# set plugin path directories here, separate with colons
#action_plugins     = /usr/share/ansible/plugins/action
#cache_plugins      = /usr/share/ansible/plugins/cache
#callback_plugins   = /usr/share/ansible/plugins/callback
#connection_plugins = /usr/share/ansible/plugins/connection
#lookup_plugins     = /usr/share/ansible/plugins/lookup
#inventory_plugins  = /usr/share/ansible/plugins/inventory
#vars_plugins       = /usr/share/ansible/plugins/vars
#filter_plugins     = /usr/share/ansible/plugins/filter
#test_plugins       = /usr/share/ansible/plugins/test
#terminal_plugins   = /usr/share/ansible/plugins/terminal
#strategy_plugins   = /usr/share/ansible/plugins/strategy


# by default, ansible will use the 'linear' strategy but you may want to try
# another one
#strategy = free

# by default callbacks are not loaded for /bin/ansible, enable this if you
# want, for example, a notification or logging callback to also apply to
# /bin/ansible runs
#bin_ansible_callbacks = False


# don't like cows?  that's unfortunate.
# set to 1 if you don't want cowsay support or export ANSIBLE_NOCOWS=1
#nocows = 1

# set which cowsay stencil you'd like to use by default. When set to 'random',
# a random stencil will be selected for each task. The selection will be filtered
# against the `cow_whitelist` option below.
#cow_selection = default
#cow_selection = random

# when using the 'random' option for cowsay, stencils will be restricted to this list.
# it should be formatted as a comma-separated list with no spaces between names.
# NOTE: line continuations here are for formatting purposes only, as the INI parser
#       in python does not support them.
#cow_whitelist=bud-frogs,bunny,cheese,daemon,default,dragon,elephant-in-snake,elephant,eyes,\
#              hellokitty,kitty,luke-koala,meow,milk,moofasa,moose,ren,sheep,small,stegosaurus,\
#              stimpy,supermilker,three-eyes,turkey,turtle,tux,udder,vader-koala,vader,www

# don't like colors either?
# set to 1 if you don't want colors, or export ANSIBLE_NOCOLOR=1
#nocolor = 1

# if set to a persistent type (not 'memory', for example 'redis') fact values
# from previous runs in Ansible will be stored.  This may be useful when
# wanting to use, for example, IP information from one group of servers
# without having to talk to them in the same playbook run to get their
# current IP information.
#fact_caching = memory


# retry files
# When a playbook fails by default a .retry file will be created in ~/
# You can disable this feature by setting retry_files_enabled to False
# and you can change the location of the files by setting retry_files_save_path

#retry_files_enabled = False
#retry_files_save_path = ~/.ansible-retry

# squash actions
# Ansible can optimise actions that call modules with list parameters
# when looping. Instead of calling the module once per with_ item, the
# module is called once with all items at once. Currently this only works
# under limited circumstances, and only with parameters named 'name'.
#squash_actions = apk,apt,dnf,homebrew,pacman,pkgng,yum,zypper

# prevents logging of task data, off by default
#no_log = False

# prevents logging of tasks, but only on the targets, data is still logged on the master/controller
#no_target_syslog = False

# controls whether Ansible will raise an error or warning if a task has no
# choice but to create world readable temporary files to execute a module on
# the remote machine.  This option is False by default for security.  Users may
# turn this on to have behaviour more like Ansible prior to 2.1.x.  See
# https://docs.ansible.com/ansible/become.html#becoming-an-unprivileged-user
# for more secure ways to fix this than enabling this option.
#allow_world_readable_tmpfiles = False

# controls the compression level of variables sent to
# worker processes. At the default of 0, no compression
# is used. This value must be an integer from 0 to 9.
#var_compression_level = 9

# controls what compression method is used for new-style ansible modules when
# they are sent to the remote system.  The compression types depend on having
# support compiled into both the controller's python and the client's python.
# The names should match with the python Zipfile compression types:
# * ZIP_STORED (no compression. available everywhere)
# * ZIP_DEFLATED (uses zlib, the default)
# These values may be set per host via the ansible_module_compression inventory
# variable
#module_compression = 'ZIP_DEFLATED'

# This controls the cutoff point (in bytes) on --diff for files
# set to 0 for unlimited (RAM may suffer!).
#max_diff_size = 1048576

# This controls how ansible handles multiple --tags and --skip-tags arguments
# on the CLI.  If this is True then multiple arguments are merged together.  If
# it is False, then the last specified argument is used and the others are ignored.
# This option will be removed in 2.8.
#merge_multiple_cli_flags = True

# Controls showing custom stats at the end, off by default
#show_custom_stats = True

# Controls which files to ignore when using a directory as inventory with
# possibly multiple sources (both static and dynamic)
#inventory_ignore_extensions = ~, .orig, .bak, .ini, .cfg, .retry, .pyc, .pyo

# This family of modules use an alternative execution path optimized for network appliances
# only update this setting if you know how this works, otherwise it can break module execution
#network_group_modules=['eos', 'nxos', 'ios', 'iosxr', 'junos', 'vyos']

# When enabled, this option allows lookups (via variables like {{lookup('foo')}} or when used as
# a loop with `with_foo`) to return data that is not marked "unsafe". This means the data may contain
# jinja2 templating language which will be run through the templating engine.
# ENABLING THIS COULD BE A SECURITY RISK
#allow_unsafe_lookups = False

# set default errors for all plays
#any_errors_fatal = False

[inventory]
# enable inventory plugins, default: 'host_list', 'script', 'yaml', 'ini'
#enable_plugins = host_list, virtualbox, yaml, constructed

# ignore these extensions when parsing a directory as inventory source
#ignore_extensions = .pyc, .pyo, .swp, .bak, ~, .rpm, .md, .txt, ~, .orig, .ini, .cfg, .retry

# ignore files matching these patterns when parsing a directory as inventory source
#ignore_patterns=

# If 'true' unparsed inventory sources become fatal errors, they are warnings otherwise.
#unparsed_is_failed=False

[privilege_escalation]
#become=True
#become_method=sudo
#become_user=root
#become_ask_pass=False

[paramiko_connection]

# uncomment this line to cause the paramiko connection plugin to not record new host
# keys encountered.  Increases performance on new host additions.  Setting works independently of the
# host key checking setting above.
#record_host_keys=False

# by default, Ansible requests a pseudo-terminal for commands executed under sudo. Uncomment this
# line to disable this behaviour.
#pty=False

# paramiko will default to looking for SSH keys initially when trying to
# authenticate to remote devices.  This is a problem for some network devices
# that close the connection after a key failure.  Uncomment this line to
# disable the Paramiko look for keys function
#look_for_keys = False

# When using persistent connections with Paramiko, the connection runs in a
# background process.  If the host doesn't already have a valid SSH key, by
# default Ansible will prompt to add the host key.  This will cause connections
# running in background processes to fail.  Uncomment this line to have
# Paramiko automatically add host keys.
#host_key_auto_add = True

[ssh_connection]
pipelining=true
# ssh arguments to use
# Leaving off ControlPersist will result in poor performance, so use
# paramiko on older platforms rather than removing it, -C controls compression use
#ssh_args = -C -o ControlMaster=auto -o ControlPersist=60s

# The base directory for the ControlPath sockets. 
# This is the "%(directory)s" in the control_path option
# 
# Example: 
# control_path_dir = /tmp/.ansible/cp
#control_path_dir = ~/.ansible/cp

# The path to use for the ControlPath sockets. This defaults to a hashed string of the hostname, 
# port and username (empty string in the config). The hash mitigates a common problem users 
# found with long hostames and the conventional %(directory)s/ansible-ssh-%%h-%%p-%%r format. 
# In those cases, a "too long for Unix domain socket" ssh error would occur.
#
# Example:
# control_path = %(directory)s/%%h-%%r
#control_path =

# Enabling pipelining reduces the number of SSH operations required to
# execute a module on the remote server. This can result in a significant
# performance improvement when enabled, however when using "sudo:" you must
# first disable 'requiretty' in /etc/sudoers
#
# By default, this option is disabled to preserve compatibility with
# sudoers configurations that have requiretty (the default on many distros).
#
#pipelining = False

# Control the mechanism for transferring files (old)
#   * smart = try sftp and then try scp [default]
#   * True = use scp only
#   * False = use sftp only
#scp_if_ssh = smart

# Control the mechanism for transferring files (new)
# If set, this will override the scp_if_ssh option
#   * sftp  = use sftp to transfer files
#   * scp   = use scp to transfer files
#   * piped = use 'dd' over SSH to transfer files
#   * smart = try sftp, scp, and piped, in that order [default]
#transfer_method = smart

# if False, sftp will not use batch mode to transfer files. This may cause some
# types of file transfer failures impossible to catch however, and should
# only be disabled if your sftp version has problems with batch mode
#sftp_batch_mode = False

[persistent_connection]

# Configures the persistent connection timeout value in seconds.  This value is
# how long the persistent connection will remain idle before it is destroyed.  
# If the connection doesn't receive a request before the timeout value 
# expires, the connection is shutdown. The default value is 30 seconds.
#connect_timeout = 30

# Configures the persistent connection retry timeout.  This value configures the
# the retry timeout that ansible-connection will wait to connect
# to the local domain socket. This value must be larger than the
# ssh timeout (timeout) and less than persistent connection idle timeout (connect_timeout).
# The default value is 15 seconds.
#connect_retry_timeout = 15

# The command timeout value defines the amount of time to wait for a command
# or RPC call before timing out. The value for the command timeout must
# be less than the value of the persistent connection idle timeout (connect_timeout)
# The default value is 10 second.
#command_timeout = 10

[accelerate]
#accelerate_port = 5099
#accelerate_timeout = 30
#accelerate_connect_timeout = 5.0

# The daemon timeout is measured in minutes. This time is measured
# from the last activity to the accelerate daemon.
#accelerate_daemon_timeout = 30

# If set to yes, accelerate_multi_key will allow multiple
# private keys to be uploaded to it, though each user must
# have access to the system via SSH to add a new key. The default
# is "no".
#accelerate_multi_key = yes

[selinux]
# file systems that require special treatment when dealing with security context
# the default behaviour that copies the existing context or uses the user default
# needs to be changed to use the file system dependent context.
#special_context_filesystems=nfs,vboxsf,fuse,ramfs,9p

# Set this to yes to allow libvirt_lxc connections to work without SELinux.
#libvirt_lxc_noseclabel = yes

[colors]
#highlight = white
#verbose = blue
#warn = bright purple
#error = red
#debug = dark gray
#deprecate = purple
#skip = cyan
#unreachable = red
#ok = green
#changed = yellow
#diff_add = green
#diff_remove = red
#diff_lines = cyan


[diff]
# Always print diff when running ( same as always running with -D/--diff )
# always = no

# Set how many context lines to show in diff
# context = 3

]0;root@ansibleprod:/etc/ansibleYou have mail in /var/spool/mail/root
[root@ansibleprod ansible]# cat ansible.cfg[6Phostsls[Kcat hosts
#sas-micro-01.magma.co.in
#sas-cas-01.magma.co.in
172.100.10.105
]0;root@ansibleprod:/etc/ansible[root@ansibleprod ansible]# 
]0;root@ansibleprod:/etc/ansible[root@ansibleprod ansible]# cat hostsansible.cfg[6Phostsls[K
ansible.cfg  [0m[01;32mhosts[0m
]0;root@ansibleprod:/etc/ansible[root@ansibleprod ansible]# 
]0;root@ansibleprod:/etc/ansible[root@ansibleprod ansible]# 
]0;root@ansibleprod:/etc/ansible[root@ansibleprod ansible]# pwd
/etc/ansible
]0;root@ansibleprod:/etc/ansible[root@ansibleprod ansible]# 
]0;root@ansibleprod:/etc/ansible[root@ansibleprod ansible]# 
]0;root@ansibleprod:/etc/ansible[root@ansibleprod ansible]# ca[K[Kcd /e[Kroot/
]0;root@ansibleprod:~[root@ansibleprod ~]# ls
[0m[01;32m172.100.10.105[0m     [01;34mbin[0m               server.txt           test.key
2.py               [01;34m~None[0m             session.root.28619.  test.py
2.pyc              [01;32mopenssl[0m           [01;34mshc-3.8.7[0m            typescript
anaconda-ks.cfg    [01;32mpwc_Linux.sh[0m      [01;31mshc-3.8.7.tgz[0m        xml_to_html_util.php
[01;34mattendance[0m         [01;32mpwc.sh[0m            test
[01;34mawscli-bundle[0m      [01;34mscripts[0m           test.
[01;31mawscli-bundle.zip[0m  [01;32mserversshcopy.sh[0m  test.csr
]0;root@ansibleprod:~[root@ansibleprod ~]# cat 172.100.10.105
#!/bin/sh


######################################################################################################
#                      Prasanth Boggarapu
#                       Hardening Script
#                       
#
#
#
#
#
#
#######################################################################################################


rm -rf /tmp/harden.out

#Use Only Approved Cipher inCounter mode
sed -i '1i\Ciphers aes128-ctr,aes192-ctr,aes256-ctr\' /etc/ssh/sshd_config
sed -i '2i\MACs hmac-sha1,hmac-ripemd160\' /etc/ssh/sshd_config
awk  '/Ciphers aes128-ctr,aes192-ctr,aes256-ctr/{print $0}' /etc/ssh/sshd_config >> /tmp/harden.out
awk  '/MACs hmac-sha1,hmac-ripemd160/{print $0}' /etc/ssh/sshd_config >> /tmp/harden.out
sleep 5

## disable iptables and selinux

service iptables stop >> /tmp/harden.out
chkconfig iptables off >> /tmp/harden.out
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
awk '/SELINUX/{print $0}' /etc/selinux/config >> /tmp/harden.out


#store password in encryption format
authconfig --passalgo=sha512 --update

#set password Creation Requirement parameter using pam_cracklib
sed -i 's/try_first_pass retry=3 type=/try_first_pass retry=3 minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1/g' /etc/pam.d/system-auth
grep pam_cracklib.so /etc/pam.d/system-auth >> /tmp/harden.out
sleep 1

#Limit password Reuse
sed -i 's/pam_unix.so sha512 shadow nullok try_first_pass use_authtok/pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5'/g /etc/pam.d/system-auth
grep pam_unix.so /etc/pam.d/system-auth >> /tmp/harden.out
sleep 1

##### Enabling Strong Ciphers in HTTPD######

sed -i 's/SSLProtocol all -SSLv2/SSLProtocol -All +TLSv1 +TLSv1.1 +TLSv1.2/g' /etc/httpd/conf.d/ssl.conf
sed -i 's/SSLCipherSuite DEFAULT:!EXP:!SSLv2:!DES:!IDEA:!SEED:+3DES/SSLCipherSuite ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS/g' /etc/httpd/conf.d/ssl.conf
awk  '/SSLProtocol/{print $0}' /etc/httpd/conf.d/ssl.conf >> /tmp/harden.out
awk  '/SSLCipherSuite/{print $0}' /etc/httpd/conf.d/ssl.conf >> /tmp/harden.out

sleep 1

######### Heart bleed vulnerability closing######

export http_proxy=http://msurveyapp:Zaq12wsX@172.17.7.252:3521
export https_proxy=http://msurveyapp:Zaq12wsX@172.17.7.252:3521
export ftp_proxy=http://msurveyapp:Zaq12wsX@172.17.7.252:3521
subscription-manager register --username magmashrachi --password M@gm@123 --auto-attach && yum -y update openssl* >> /tmp/harden.out

######## Disbale trace in and track in httpd ########

sed -i '95i\RewriteEngine on\' /etc/httpd/conf.d/ssl.conf
sed -i '96i\RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)\'  /etc/httpd/conf.d/ssl.conf
sed -i '97i\RewriteRule .* - [F]\'  /etc/httpd/conf.d/ssl.conf

awk  '/RewriteEngine on/{print $0}' /etc/httpd/conf.d/ssl.conf >> /tmp/harden.out
awk  '/RewriteCond/{print $0}'  /etc/httpd/conf.d/ssl.conf >> /tmp/harden.out
awk  '/RewriteRule/{print $0}' /etc/httpd/conf.d/ssl.conf >> /tmp/harden.out
#######

sleep 5

#service httpd restart >> /tmp/harden.out

#restrict deamon
rm /etc/at.deny >> /tmp/harden.out
touch /etc/at.allow >> /tmp/harden.out
chown root:root /etc/at.allow
chmod og-rwx /etc/at.allow

#Restrict at/cron to authorized users
/bin/rm /etc/cron.deny
/bin/rm /etc/at.deny
chmod og-rwx /etc/at.allow
chown root:root /etc/at.allow

#Set SHH Protocal to 2
sed -i 's/Protocol [^ ]*/Protocol 2/g' /etc/ssh/sshd_config
awk  '/Protocol 2/{print $0}' /etc/ssh/sshd_config >> /tmp/harden.out


#Set SSH PermitEmptyPassword to No
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
awk  '/PermitEmptyPasswords[^ ]*/{print $0}' /etc/ssh/sshd_config >> /tmp/harden.out

#Do NOT Allow Users to Set Environment Options
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config
awk  '/PermitUserEnvironment[^ ]*/{print $0}' /etc/ssh/sshd_config >> /tmp/harden.out

#Use Only Approved Cipher inCounter mode
#sed -i '140i\Ciphers aes128-ctr,aes192-ctr,aes256-ctr\' /etc/ssh/sshd_config
#awk  '/Ciphers aes128-ctr,aes192-ctr,aes256-ctr/{print $0}' /etc/ssh/sshd_config >> /tmp/harden.out
#sleep 5

service sshd restart
#restrict access to critical files
chown root:root /etc/passwd /etc/shadow /etc/group
chmod 644 /etc/passwd /etc/group
chmod 400 /etc/shadow
ls -ld /etc/passwd /etc/shadow /etc/group >> /tmp/harden.out
sleep 2


#Remove the non-Essential Services
chkconfig apmd off
chkconfig atd off
chkconfig autofs off
chkconfig chargen off
chkconfig chargen-dup off
chkconfig cups off
chkconfig cups-lpd off
chkconfig daytime-udp off
chkconfig echo off
chkconfig echo-udp off
chkconfig eklogin off
chkconfig gssftp off
chkconfig irda off
chkconfig irqbalance off
chkconfig isdn off
chkconfig klogin off
chkconfig krb-telnet off
chkconfig kshell off
chkconfig mdmonitor off
chkconfig mdmpd off
chkconfig microcode_ctl off
chkconfig named off
chkconfig netdump off
chkconfig netfs off
chkconfig nfslock off
chkconfig pcmcia off
chkconfig portmap off
chkconfig pssacct off
chkconfig random off
chkconfig rawdevices off
chkconfig rhnsd off
chkconfig rsync off
chkconfig saslauthd off
chkconfig sendmail off
chkconfig smartd off
chkconfig smb off
chkconfig snmpd off
chkconfig snmptrapd off
chkconfig swat off
chkconfig time off
chkconfig time-udp off
chkconfig vncserver off
chkconfig windbind off
chkconfig --list | grep '3:off' >> /tmp/harden.out
sleep 2


#configure strong permission on temporary folders
cd /
chmod 1777 tmp
chmod 1777 utmp
chmod 1777 utmpx

#configure strong permission on log files
chmod 622 /var/log/messages
chmod 622 /var/log/secure
chmod 622 /var/log/spooler
chmod 622 /var/log/maillog
chmod 622 /var/log/cron
chmod 622 /var/log/boot.log

#Configure Audit Log Storage Size
sed -i 's/max_log_file = [^ ]*/max_log_file = 100/g' /etc/audit/auditd.conf
awk '/max_log_file = [^ ]*/{print $0}' /etc/audit/auditd.conf >> /tmp/harden.out

#configure Strong System Mask
sed -i 's/umask [^ ]*/umask 022/g' /etc/bashrc


#Login and logon Events should be audited
echo  "-w /var/log/faillog -p wa -k logins" >> /etc/audit/audit.rules
echo  "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/audit.rules
echo  "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/audit.rules
pkill -HUP -P 1 auditd
awk '/ -p wa -k logins/ {print $0}' /etc/audit/audit.rules >> /tmp/harden.out
awk '/ -p wa -k logins/ {print $0}' /etc/audit/audit.rules >> /tmp/harden.out
awk '/ -p wa -k logins/ {print $0}' /etc/audit/audit.rules >> /tmp/harden.out
sleep 2

#Permission on /etc/passwd
/bin/chmod 644 /etc/passwd
ls -ld /etc/passwd >> /tmp/harden.out

#permission on /etc/shadow
/bin/chmod 000 /etc/shadow
ls -ld /etc/shadow >> /tmp/harden.out

#permission on /etc/gshadow
/bin/chmod 000 /etc/gshadow
ls -ld /etc/gshadow >> /tmp/harden.out
#permission on /etc/group
/bin/chown 644 /etc/group
ls -ld /etc/group >> /tmp/harden.out
#verify user/group Ownership on /etc/passwd
/bin/chown root:root /etc/passwd
ls -lrt /etc/passwd >> /tmp/harden.out
#verify user/group Ownership on /etc/shadow
/bin/chown root:root /etc/shadow
ls -lrt /etc/shadow >> /tmp/harden.out
#verify user/group Ownership on /etc/gshadow
/bin/chown root:root /etc/gshadow
ls -lrt /etc/gshadow >> /tmp/harden.out
#verify user/group Ownership on /etc/group
chown root:root /etc/group
ls -lrt /etc/group >> /tmp/harden.out
sleep 2






echo " Hi All,
           Please find the below output file of server hardening.
Thanks,
Prasanth Boggavarapu,
Dc Linux,
Prasanth B." > hardening.txt
mailx -r dc.linux@magma.co.in -s " $(hostname) server hardening output file" -a /tmp/harden.out dc.linux@magma.co.in, devandla.madhu@magma.co.in, dc.pm@magma.co.in, dey.ranjan@magma.co.in < hardening.txt

]0;root@ansibleprod:~[root@ansibleprod ~]# cat server.txt
]0;root@ansibleprod:~You have mail in /var/spool/mail/root
[root@ansibleprod ~]# cat server.txt[K[K[K[K[K[K[K[K[K[K[K[K[K[Kl
bash: l: command not found...
]0;root@ansibleprod:~[root@ansibleprod ~]# ls
[0m[01;32m172.100.10.105[0m     [01;34mbin[0m               server.txt           test.key
2.py               [01;34m~None[0m             session.root.28619.  test.py
2.pyc              [01;32mopenssl[0m           [01;34mshc-3.8.7[0m            typescript
anaconda-ks.cfg    [01;32mpwc_Linux.sh[0m      [01;31mshc-3.8.7.tgz[0m        xml_to_html_util.php
[01;34mattendance[0m         [01;32mpwc.sh[0m            test
[01;34mawscli-bundle[0m      [01;34mscripts[0m           test.
[01;31mawscli-bundle.zip[0m  [01;32mserversshcopy.sh[0m  test.csr
]0;root@ansibleprod:~[root@ansibleprod ~]# cat typescript
]0;root@ansibleprod:~[root@ansibleprod ~]# cd scripts
]0;root@ansibleprod:~/scripts[root@ansibleprod scripts]# ls
[0m[01;32mhardening-script.sh[0m  magmatime1.sh  [01;32mmagmatime.sh[0m
]0;root@ansibleprod:~/scripts[root@ansibleprod scripts]# cat hardening-script.sh
#!/bin/sh

#Use Only Approved Cipher inCounter mode
sed -i '1i\Ciphers aes128-ctr,aes192-ctr,aes256-ctr\' /etc/ssh/sshd_config
sed -i '2i\MACs hmac-sha1,hmac-ripemd160\' /etc/ssh/sshd_config
awk  '/Ciphers aes128-ctr,aes192-ctr,aes256-ctr/{print $0}' /etc/ssh/sshd_config
awk  '/MACs hmac-sha1,hmac-ripemd160/{print $0}' /etc/ssh/sshd_config
sleep 5

## disable iptables and selinux

service iptables stop
chkconfig iptables off
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
awk '/SELINUX/{print $0}' /etc/selinux/config


#store password in encryption format
authconfig --passalgo=sha512 --update

#set password Creation Requirement parameter using pam_cracklib
sed -i 's/try_first_pass retry=3 type=/try_first_pass retry=3 minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1/g' /etc/pam.d/system-auth
grep pam_cracklib.so /etc/pam.d/system-auth
sleep 1

#Limit password Reuse
sed -i 's/pam_unix.so sha512 shadow nullok try_first_pass use_authtok/pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5'/g /etc/pam.d/system-auth
grep pam_unix.so /etc/pam.d/system-auth
sleep 1

##### Enabling Strong Ciphers in HTTPD######

sed -i 's/SSLProtocol all -SSLv2/SSLProtocol -All +TLSv1 +TLSv1.1 +TLSv1.2/g' /etc/httpd/conf.d/ssl.conf
sed -i 's/SSLCipherSuite DEFAULT:!EXP:!SSLv2:!DES:!IDEA:!SEED:+3DES/SSLCipherSuite ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS/g' /etc/httpd/conf.d/ssl.conf
awk  '/SSLProtocol/{print $0}' /etc/httpd/conf.d/ssl.conf
awk  '/SSLCipherSuite/{print $0}' /etc/httpd/conf.d/ssl.conf

sleep 1

######### Heart bleed vulnerability closing######

export http_proxy=http://msurveyapp:Zaq12wsX@172.17.7.252:3521
export https_proxy=http://msurveyapp:Zaq12wsX@172.17.7.252:3521
export ftp_proxy=http://msurveyapp:Zaq12wsX@172.17.7.252:3521
subscription-manager register --username magmashrachi --password M@gm@123 --auto-attach && yum -y update openssl*

######## Disbale trace in and track in httpd ########

sed -i '95i\RewriteEngine on\' /etc/httpd/conf.d/ssl.conf
sed -i '96i\RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)\'  /etc/httpd/conf.d/ssl.conf
sed -i '97i\RewriteRule .* - [F]\'  /etc/httpd/conf.d/ssl.conf

awk  '/RewriteEngine on/{print $0}' /etc/httpd/conf.d/ssl.conf
awk  '/RewriteCond/{print $0}'  /etc/httpd/conf.d/ssl.conf
awk  '/RewriteRule/{print $0}' /etc/httpd/conf.d/ssl.conf
#######

sleep 5

service httpd restart

#restrict deamon
rm /etc/at.deny
touch /etc/at.allow
chown root:root /etc/at.allow
chmod og-rwx /etc/at.allow

#Restrict at/cron to authorized users
/bin/rm /etc/cron.deny
/bin/rm /etc/at.deny
chmod og-rwx /etc/at.allow
chown root:root /etc/at.allow

#Set SHH Protocal to 2
sed -i 's/Protocol [^ ]*/Protocol 2/g' /etc/ssh/sshd_config
awk  '/Protocol 2/{print $0}' /etc/ssh/sshd_config


#Set SSH PermitEmptyPassword to No
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
awk  '/PermitEmptyPasswords[^ ]*/{print $0}' /etc/ssh/sshd_config

#Do NOT Allow Users to Set Environment Options
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config
awk  '/PermitUserEnvironment[^ ]*/{print $0}' /etc/ssh/sshd_config

#Use Only Approved Cipher inCounter mode
#sed -i '140i\Ciphers aes128-ctr,aes192-ctr,aes256-ctr\' /etc/ssh/sshd_config
#awk  '/Ciphers aes128-ctr,aes192-ctr,aes256-ctr/{print $0}' /etc/ssh/sshd_config
#sleep 5

service sshd restart
#restrict access to critical files
chown root:root /etc/passwd /etc/shadow /etc/group
chmod 644 /etc/passwd /etc/group
chmod 400 /etc/shadow
ls -ld /etc/passwd /etc/shadow /etc/group
sleep 2


cd /
chmod 1777 tmp
chmod 1777 utmp
chmod 1777 utmpx

#configure strong permission on log files
chmod 622 /var/log/messages
chmod 622 /var/log/secure
chmod 622 /var/log/spooler
chmod 622 /var/log/maillog
chmod 622 /var/log/cron
chmod 622 /var/log/boot.log

#Configure Audit Log Storage Size
sed -i 's/max_log_file = [^ ]*/max_log_file = 100/g' /etc/audit/auditd.conf
awk '/max_log_file = [^ ]*/{print $0}' /etc/audit/auditd.conf

#configure Strong System Mask
sed -i 's/umask [^ ]*/umask 022/g' /etc/bashrc


#Login and logon Events should be audited
echo  "-w /var/log/faillog -p wa -k logins" >> /etc/audit/audit.rules
echo  "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/audit.rules
echo  "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/audit.rules
pkill -HUP -P 1 auditd
awk '/ -p wa -k logins/ {print $0}' /etc/audit/audit.rules
awk '/ -p wa -k logins/ {print $0}' /etc/audit/audit.rules
awk '/ -p wa -k logins/ {print $0}' /etc/audit/audit.rules
sleep 2

#Permission on /etc/passwd
/bin/chmod 644 /etc/passwd
ls -ld /etc/passwd

#permission on /etc/shadow
/bin/chmod 000 /etc/shadow
ls -ld /etc/shadow

#permission on /etc/gshadow
/bin/chmod 000 /etc/gshadow
ls -ld /etc/gshadow
#permission on /etc/group
/bin/chown 644 /etc/group
ls -ld /etc/group
#verify user/group Ownership on /etc/passwd
/bin/chown root:root /etc/passwd
ls -lrt /etc/passwd
#verify user/group Ownership on /etc/shadow
/bin/chown root:root /etc/shadow
ls -lrt /etc/shadow
#verify user/group Ownership on /etc/gshadow
/bin/chown root:root /etc/gshadow
ls -lrt /etc/gshadow
#verify user/group Ownership on /etc/group
chown root:root /etc/group
ls -lrt /etc/group
sleep 2
]0;root@ansibleprod:~/scripts[root@ansibleprod scripts]# cat hardening-script.sh[K[K[K[K[K[K[K[K[K[K[K[K[K[K[K[K[K[K[K[K[K[K[Kls
[0m[01;32mhardening-script.sh[0m  magmatime1.sh  [01;32mmagmatime.sh[0m
]0;root@ansibleprod:~/scripts[root@ansibleprod scripts]# cat magmatime1.sh
]0;root@ansibleprod:~/scripts[root@ansibleprod scripts]# cat magmatime.sh
rm -rf /etc/profile.d/custom.sh
mkdir -p /var/log/session/ 
]0;root@ansibleprod:~/scripts[root@ansibleprod scripts]# 
]0;root@ansibleprod:~/scripts[root@ansibleprod scripts]# 
]0;root@ansibleprod:~/scripts[root@ansibleprod scripts]# 
]0;root@ansibleprod:~/scriptsYou have mail in /var/spool/mail/root
[root@ansibleprod scripts]# 
]0;root@ansibleprod:~/scripts[root@ansibleprod scripts]# 
]0;root@ansibleprod:~/scripts[root@ansibleprod scripts]# ls
[0m[01;32mhardening-script.sh[0m  magmatime1.sh  [01;32mmagmatime.sh[0m
]0;root@ansibleprod:~/scripts[root@ansibleprod scripts]# 
]0;root@ansibleprod:~/scripts[root@ansibleprod scripts]# 
]0;root@ansibleprod:~/scripts[root@ansibleprod scripts]# cd ..
]0;root@ansibleprod:~[root@ansibleprod ~]# ls
[0m[01;32m172.100.10.105[0m     [01;34mbin[0m               server.txt           test.key
2.py               [01;34m~None[0m             session.root.28619.  test.py
2.pyc              [01;32mopenssl[0m           [01;34mshc-3.8.7[0m            typescript
anaconda-ks.cfg    [01;32mpwc_Linux.sh[0m      [01;31mshc-3.8.7.tgz[0m        xml_to_html_util.php
[01;34mattendance[0m         [01;32mpwc.sh[0m            test
[01;34mawscli-bundle[0m      [01;34mscripts[0m           test.
[01;31mawscli-bundle.zip[0m  [01;32mserversshcopy.sh[0m  test.csr
]0;root@ansibleprod:~[root@ansibleprod ~]# cat serversshcopy.sh\[K
while read fk
do
echo y | ssh-copy-id $fk
done < /root/server.txt
]0;root@ansibleprod:~[root@ansibleprod ~]# 
]0;root@ansibleprod:~[root@ansibleprod ~]# cat pwc_Linux.sh
#!/bin/bash
echo "Gathering information......"

echo "CPU Information----------------------------" 1>/tmp/$(hostname)
cat /proc/cpuinfo 1>>/tmp/$(hostname)

echo "Network Interface Information--------------" 1>>/tmp/$(hostname)
ifconfig -a 1>>/tmp/$(hostname)

echo "System Kernel Information------------------" 1>>/tmp/$(hostname)
dmesg 1>>/tmp/$(hostname)

echo "Kernel Modules-----------------------------" 1>>/tmp/$(hostname)
/sbin/lsmod 1>>/tmp/$(hostname)

echo "PCI Information----------------------------" 1>>/tmp/$(hostname)
/sbin/lspci 1>>/tmp/$(hostname)

echo "PC BIOS Information------------------------" 1>>/tmp/$(hostname)
/usr/sbin/dmidecode 1>>/tmp/$(hostname)

echo "Network Stats------------------------------" 1>>/tmp/$(hostname)
netstat -in 1>>/tmp/$(hostname)

echo "Running Processes--------------------------" 1>>/tmp/$(hostname)
ps -ef 1>>/tmp/$(hostname)

echo "Software Packages--------------------------" 1>>/tmp/$(hostname)
rpm -qa 1>>/tmp/$(hostname)

echo "Application Installations------------------" 1>>/tmp/$(hostname)
echo "/usr: Details------------------------------" 1>>/tmp/$(hostname)
ls /usr 1>>/tmp/$(hostname)

echo "/usr/bin: Details------------------------------" 1>>/tmp/$(hostname)
ls /usr/bin 1>>/tmp/$(hostname)

echo "/usr/sbin: Details------------------------------" 1>>/tmp/$(hostname)
ls /usr/sbin 1>>/tmp/$(hostname)

echo "/usr/local: Details------------------------------" 1>>/tmp/$(hostname)
ls /usr/local 1>>/tmp/$(hostname)

echo "/usr/local/bin: Details---------------------------" 1>>/tmp/$(hostname)
ls /usr/local/bin 1>>/tmp/$(hostname)

echo "/usr/local/sbin: Details---------------------------" 1>>/tmp/$(hostname)
ls /usr/local/sbin 1>>/tmp/$(hostname)



echo "Script execution successful!!"

]0;root@ansibleprod:~[root@ansibleprod ~]# 
]0;root@ansibleprod:~You have mail in /var/spool/mail/root
[root@ansibleprod ~]# ls
[0m[01;32m172.100.10.105[0m     [01;34mbin[0m               server.txt           test.key
2.py               [01;34m~None[0m             session.root.28619.  test.py
2.pyc              [01;32mopenssl[0m           [01;34mshc-3.8.7[0m            typescript
anaconda-ks.cfg    [01;32mpwc_Linux.sh[0m      [01;31mshc-3.8.7.tgz[0m        xml_to_html_util.php
[01;34mattendance[0m         [01;32mpwc.sh[0m            test
[01;34mawscli-bundle[0m      [01;34mscripts[0m           test.
[01;31mawscli-bundle.zip[0m  [01;32mserversshcopy.sh[0m  test.csr
]0;root@ansibleprod:~[root@ansibleprod ~]# cat test
]0;root@ansibleprod:~[root@ansibleprod ~]# cat openssl
#!/bin/bash
echo "Gathering information......"

echo "CPU Information----------------------------" 1>$(hostname)
cat /proc/cpuinfo 1>>$(hostname).text

echo "Network Interface Information--------------" 1>>$(hostname)
ifconfig -a 1>>$(hostname)

echo "System Kernel Information------------------" 1>>$(hostname)
dmesg 1>>$(hostname)

echo "Kernel Modules-----------------------------" 1>>$(hostname)
/sbin/lsmod 1>>$(hostname)

echo "PCI Information----------------------------" 1>>$(hostname)
/sbin/lspci 1>>$(hostname)

echo "PC BIOS Information------------------------" 1>>$(hostname)
/usr/sbin/dmidecode 1>>$(hostname)

echo "Network Stats------------------------------" 1>>$(hostname)
netstat -in 1>>$(hostname)

echo "Running Processes--------------------------" 1>>$(hostname)
ps -ef 1>>$(hostname)

echo "Software Packages--------------------------" 1>>$(hostname)
rpm -qa 1>>$(hostname)

echo "Application Installations------------------" 1>>$(hostname)
echo "/usr: Details------------------------------" 1>>$(hostname)
ls /usr 1>>$(hostname)

echo "/usr/bin: Details------------------------------" 1>>$(hostname)
ls /usr/bin 1>>$(hostname)

echo "/usr/sbin: Details------------------------------" 1>>$(hostname)
ls /usr/sbin 1>>$(hostname)

echo "/usr/local: Details------------------------------" 1>>$(hostname)
ls /usr/local 1>>$(hostname)

echo "/usr/local/bin: Details---------------------------" 1>>$(hostname)
ls /usr/local/bin 1>>$(hostname)

echo "/usr/local/sbin: Details---------------------------" 1>>$(hostname)
ls /usr/local/sbin 1>>$(hostname)



echo "Script execution successful!!"
]0;root@ansibleprod:~[root@ansibleprod ~]# cd awscli-bundle
]0;root@ansibleprod:~/awscli-bundleYou have mail in /var/spool/mail/root
[root@ansibleprod awscli-bundle]# ls
[0m[01;32minstall[0m  [01;34mpackages[0m
]0;root@ansibleprod:~/awscli-bundle[root@ansibleprod awscli-bundle]# cd ..
]0;root@ansibleprod:~[root@ansibleprod ~]# ls
[0m[01;32m172.100.10.105[0m     [01;34mbin[0m               server.txt           test.key
2.py               [01;34m~None[0m             session.root.28619.  test.py
2.pyc              [01;32mopenssl[0m           [01;34mshc-3.8.7[0m            typescript
anaconda-ks.cfg    [01;32mpwc_Linux.sh[0m      [01;31mshc-3.8.7.tgz[0m        xml_to_html_util.php
[01;34mattendance[0m         [01;32mpwc.sh[0m            test
[01;34mawscli-bundle[0m      [01;34mscripts[0m           test.
[01;31mawscli-bundle.zip[0m  [01;32mserversshcopy.sh[0m  test.csr
]0;root@ansibleprod:~[root@ansibleprod ~]# cat 2.py
work='good'
if work == 'regular':
	print('I am bored')
	print('I must look for new job')
else:
	print(' I can continue for sometime')
]0;root@ansibleprod:~[root@ansibleprod ~]# cat session.root.28619.
]0;root@ansibleprod:~You have mail in /var/spool/mail/root
[root@ansibleprod ~]# cat test.key
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDZUrcbHomHqERV
YOtIdEynVd4N03BsUz/lp1Ooxdm6au/e+r1sC+T4quKYWqmFv1Kizqeh22U2wZZg
royc1+bQGnjOb9SQ2iCmPY4zoXnnukcg5Xcf/hHnTPHsti2ypZRHJOHUikoYMgEg
sysIi8wPwcTKfkQG3C8+FS98jxiAtzzBZMnerHp++uwxsC2kceEMAoG67e1m0tVF
56ANzA76qR14OPcmMfB55JGz+3H1dYsr4vXXSq6fFDsrNNoNnp/Ue94Jg/ZIqsf7
Ysf5ooRarDYzipjk6B8Y1/i75hIWjmUb1jEHBsYQDuNatSnCt7BBHaRuc6JCl7pB
ewryuYHfAgMBAAECggEALFvO1jFAfzkgYZD71XkvoERNo+LRorrHYxfpYpyn2X40
Yf4qJeCzpvIyeEihK5SmyGaIHuiKW0feavOV7fm/uiB9Ih3/dGWhnm0YFn/SQzNp
i1RrIVOZ0e2Jv/hbkYhsoKztj5V+lDu4sTUBBqiKSXkSswZc2k2dMv3eCH2o0bS0
kRJdiDWfYiDyQ1FYvwxZYXzwI6uXZNAyhmu6euRgIssEgcjqj2znch/x/FIhQDIB
Z8HntTToO65asUwOWzgi8o+UhQVmkZaoddH9/wcFz1npCqzqCupzsoZ951qqQM1D
dN+IyKpt24OldH5XgG9amOjK0zp+ve0T6/gkr0vjeQKBgQD/WeccIrq6mVHGW8pl
9jGPiorAN3y2Tz0lyVqXckPugDAyFlWFrnFoREFAPILrKU3MgIcHnEGw4+Thr+4B
bQL4vq6DWFMxpL/MdH03CXaoVAqRxrb1XWqkpSNEA/JLX2Gbl2YAPmlHYUne+ZqX
7ZZhrqxbZ1mxl4dwMJPXvoZ0bQKBgQDZ4BOWwiRRddqq7jqE05E0Ig/nn5RK7ga5
I5iElh5fm/WwZ6jqKQzuRLEJnr0G+Rqa5//VN0qklAmzAzutN/mObEYNRSltX9Kt
XGc5nTrT9kFV82udGjTg87FUXXXImedynLRdQUWgGPjcV2LLRJax1RI8OXbytTW5
jyabzNPn+wKBgQCVWUTV7O4gE2qDxM4VYrBMDzDmCc4UZzYRcrpcl8VpqmoF8ZAl
twi3fixX4MyFtEu/j3Dqn5bAWhpVceuXw+WYDRbO1YsbHwvbDkrqNMvE2hqwdnQu
AGxOThPZRSGiue/B7AQJonc6+4kUNBMaRyjMizhd4Y3RVBowIQlnhxTm5QKBgQDV
Td2fwV6RKhL1Odqs4/zKz3ZGzCMA4NxQMZtGYzpFXIlDNZlX9uyj8ThqNLDXvNXh
RrVfZ4x6aDy+t7GbOqvmVfaXU1jlreSyuT6OV3KaxgLdRT3cRyXx/mNkN0PzK0o/
GVAz5I1n2kr6XctpOjNW00XRFGlx4RtCGfYwnm3wNQKBgQCJUXyvb77wxzc2u7oN
A8SSvZccAoIuDs3pzy7X7qxLhFtKv3k65lesNS0Yb8KvEuVB1KiAc+5tVwJfeZe8
/fpYFPvIvp4V69z3uVNihIYNESkViivlsTa3LG/J64m5DtJP+ltfTvmoEk2fBDGd
ASLT9vCPnT8s5RwmPxeDa+KHcQ==
-----END PRIVATE KEY-----
]0;root@ansibleprod:~[root@ansibleprod ~]# cat test.key[K[K[K[K.py 
def printfirst():
	print('This is my first Python script')
def printmultiple():
	print('Extiting to learn python')
def printmul():
	printfirst()
	printmultiple()
printmul()	
]0;root@ansibleprod:~[root@ansibleprod ~]# 
]0;root@ansibleprod:~[root@ansibleprod ~]# 
]0;root@ansibleprod:~[root@ansibleprod ~]# 
]0;root@ansibleprod:~[root@ansibleprod ~]# 
]0;root@ansibleprod:~[root@ansibleprod ~]# 
