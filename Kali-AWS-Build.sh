#!/bin/bash
# Script to perform initial install of Kali
# 2022/07/07
# Regular Colors
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
NC='\033[0m' 			  # No Color

echo -e ${Green}"apt update/apt upgrade"
sudo apt -y update
sudo apt -y upgrade

sudo apt install -y golang
export GOROOT=/usr/lib/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
source /home/kali/.bashrc

toolsdir='/home/kali/tools'
windowsToolsdir='/home/kali/windowsTools'

ssh-keygen -F github.com || ssh-keyscan github.com >> ~/.ssh/known_hosts

echo -e ${Green} "System Abbreviation?"${NC}
	read -e varSystemAbbr
	mkdir '/home/kali/'$varSystemAbbr
	mkdir '/home/kali/'$varSystemAbbr'/ipLists'

	if [ -d $toolsdir ]; then
	  echo ${Green}"Begin installing tools..."${NC}
	else
	  echo "Tools directory not found. Creating directory"
	  mkdir $toolsdir
	fi

	if [ -d $windowsToolsdir ]; then
	  echo ${Green}"Begin installing tools..."${NC}
	else
	  echo "Tools directory not found. Creating directory"
	  mkdir $windowsToolsdir
	fi



cd $toolsdir

echo -e ${Green}"Begin Installing Tools"${NC}

apt install python3.10-venv

wget https://dot.net/v1/dotnet-install.sh
bash ./dotnet-install.sh -c Current

echo -e ${Green}"Downloading VSCode"${NC}
	wget https://github.com/diseric/InitialBuilds/raw/main/code_1.69.0-1657183742_amd64.deb
echo -e ${Green}"Installing AWS CLI"${NC}
	sudo dpkg -i code_1.69.0-1657183742_amd64.deb
	sudo apt install -f
	rm code_1.69.0-1657183742_amd64.deb
echo -e ${Green}"Installing AWS CLI"${NC}
	curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" 
	unzip awscliv2.zip 
echo -e ${Green}"Installed AWS CLI"${NC}
echo ${Green}"Downloading Google Chrome"${NC}
	wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
echo -e ${Green}"Installing Chrome"${NC}
	sudo apt -y install ./google-chrome-stable_current_amd64.deb
	rm https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
echo -e ${Green}"Installed Chrome"${NC}
echo -e ${Green}"Installing Windows Exploit Suggestor"${NC}
	pip install wesng 
echo -e ${Green} "Begin Cloning tools"${NC}

git clone git@github.com:andresriancho/nimbostratus.git
	cd nimbostratus
	pip install -r requirements.txt
	cd $toolsdir

git clone https://github.com/duo-labs/cloudmapper.git
	sudo apt -y install autoconf automake libtool python3.10-dev python3-tk jq openssl osslsigncode mingw-w64
	cd cloudmapper/
	python3 -m venv ./venv && source venv/bin/activate
	pip install -r requirements.txt

git clone https://github.com/nccgroup/ScoutSuite.git
	cd ScoutSuite
	virtualenv -p python3 venv
	source venv/bin/activate
	pip install -r requirements.txt



apt -y install payloadsallthethings feroxbuster oscanner redis-tools sipvicious tnscmd10g nishang odat gedit wkhtmltopdf libreoffice agrep eyewitness cme iptraf-ng
	
pip3 install -U pip
pip3 install -U pacu
pip3 install -U ldap3

go get -v github.com/Shopify/kubeaudit

pip install kube-hunter

mkdir CloudBrute
	cd CloudBrute
	wget https://github.com/0xsha/CloudBrute/releases/download/v1.0.7/cloudbrute_1.0.7_Linux_x86_64.tar.gz
	tar -xvf *.tar.gz
	cd ..

wget https://github.com/atredispartners/flamingo/releases/download/v0.0.19/flamingo-windows-amd64.exe

wget https://github.com/inguardians/peirates/releases/download/v1.1.10/peirates-linux-386.tar.xz

pip install cloudsplaining

git clone https://github.com/optiv/ScareCrow.git
	cd ScareCrow
	go get github.com/fatih/color
	go get github.com/yeka/zip
	go get github.com/josephspurrier/goversioninfo
	go build ScareCrow.go
	cd ..

git clone https://github.com/FuzzySecurity/PowerShell-Suite.git

mkdir PEASS-ng
	cd PEASS-ng
	wget https://github.com/carlospolop/PEASS-ng/releases/download/20220703/linpeas_darwin_amd64
	wget https://github.com/carlospolop/PEASS-ng/releases/download/20220703/winPEASx64.exe
	wget https://github.com/carlospolop/PEASS-ng/releases/download/20220703/winPEAS.bat
	wget https://github.com/carlospolop/PEASS-ng/releases/download/20220703/winPEASany.exe

git clone https://github.com/bitsadmin/wesng.git

go install github.com/OJ/gobuster/v3@latest

#installing ruby and rubygems to sinstall evilwinrm	
#	mkdir /temp
#	cd /temp
#	sudo apt -y install ruby
#	wget https://rubygems.org/rubygems/rubygems-3.3.17.zip
#	unzip rubygems-3.3.17.zip
#	cd rubygems-3.3.17
#	gem install evil-winrm

cd $toolsdir

git clone https://github.com/carlospolop/hacktricks.git

git clone https://github.com/PowerShellMafia/PowerSploit.git
	
	mkdir $toolsdir/exploits
	cd $toolsdir/exploits
		git clone https://github.com/nomi-sec/PoC-in-GitHub.git
		cd $windowsToolsdir
		git clone https://github.com/SecWiki/windows-kernel-exploits.git
		git clone https://github.com/abatchy17/WindowsExploits.git
	cd $toolsdir

wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64

git clone https://github.com/phillips321/adaudit.git

cd $windowsToolsdir
git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git
wget https://github.com/BloodHoundAD/BloodHound/releases/download/4.1.1/BloodHound-win32-x64.zip


apt -y install bloodhound

cd $toolsdir
git clone https://github.com/BloodHoundAD/BloodHound.git

