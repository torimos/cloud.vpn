# Prerequisites:
	- Azure Cloud 
		- Virtual Network Gateway IP: x.x.x.x
		- Virtual Network Subnet: 10.1.0.0/16
		- Connection (IKE2, route based)
		- Virtual Machine IP: 10.1.0.4
	- On-Premise
		- Local Network Gateway IP: y.y.y.y
		- Local Network Subnet: 10.0.1.0/24
		- Software VPN Gateway running on RPI3 Ethernet IP: 10.0.1.47
		- Desktop IP: 10.0.1.7
    - IPsec PSK: Secret@Shared#Key

# Outcome:
	- Bi-directional communications through VPN tunnel
	- Remote connectivity from Internet to either cloud or on-prem gateway's

# Guideline

## StrongSwan service setup & configuration for Azure site-to-site connection
```
sudo -i

apt udpate && apt install strongswan strongswan-pki

service ipsec start

# nano /etc/ipsec.secrets:
x.x.x.x : PSK Secret@Shared#Key

# nano /etc/ipsec.conf:
config setup
    # strictcrlpolicy=yes
    # uniqueids = no

conn Azure
    auto=start
    type=tunnel
    keyexchange=ikev2
    authby=secret
    ikelifetime=8h
    keylife=5h
    keyingtries=1
    #rekey=no
    left=%defaultroute
    leftid=y.y.y.y
    leftsubnet=10.0.1.0/24
    leftfirewall=yes
    right=x.x.x.x
    rightsubnet=10.1.0.0/16
    ike=aes256-sha2_256-modp1024,aes256-sha1-modp1024,aes128-sha1-modp1024!
    esp=aes256gcm16

# nano /etc/strongswan.conf:
charon {
    ...
    threads = 16
    load = aes des sha1 sha2 md5 gmp random nonce hmac stroke kernel-netlink socket-default updown
    ...
}

ipsec restart

```

## StrongSwan service setup & configuration for point-to-site connection (to local vpn)
```

# create folders
mkdir -p /pki/{private,cacerts,certs}
# gen private key to sign certs
pki --gen --type rsa --size 4096 --outform pem > /pki/private/ca-key.pem
# gen signed cert authority certificate
pki --self --ca --lifetime 3650 --in /pki/private/ca-key.pem \
         --type rsa --dn "CN=VPN root CA" --outform pem > /pki/cacerts/ca-cert.pem
# gen private key for VPN server
pki --gen --type rsa --size 4096 --outform pem > /pki/private/server-key.pem
#gen vpn server cert
pki --pub --in /pki/private/server-key.pem  --type rsa \
       | pki --issue --lifetime 1825 \
        --cacert /pki/cacerts/ca-cert.pem \
        --cakey /pki/private/ca-key.pem \
        --dn "CN=y.y.y.y" --san y.y.y.y \
        --flag serverAuth --flag ikeIntermediate --outform pem \
    > /pki/certs/server-cert.pem
# copy certs to ipsec.d
cp -r /pki/* /etc/ipsec.d/

# nano /etc/ipsec.conf:
conn test.net
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=y.y.y.y
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    leftfirewall=yes
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.0.2.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity
    ike=chacha20poly1305-sha512-curve25519-prfsha512,aes256gcm16-sha384-prfsha384-ecp384,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=chacha20poly1305-sha512,aes256gcm16-ecp384,aes256-sha256,aes256-sha1,3des-sha1!

# nano /etc/ipsec.secrets:
: RSA "server-key.pem"
user1 : EAP "user1"

# restart ipsec service to apply new params
ipsec restart

# grab ca-cert.pem and install to client (on Windows to Trusted authorities of Local Computer)
cp /etc/ipsec.d/cacerts/ca-cert.pem /home

# create vpn connection 
Add-VpnConnection -Name "VPN Connection" `
    -ServerAddress "y.y.y.y" `
    -TunnelType "IKEv2" `
    -AuthenticationMethod "EAP" `
    -EncryptionLevel "Maximum" `
    -RememberCredential

Set-VpnConnectionIPsecConfiguration -Name "VPN Connection" `
    -AuthenticationTransformConstants GCMAES256 `
    -CipherTransformConstants GCMAES256 `
    -DHGroup ECP384 `
    -IntegrityCheckMethod SHA384 `
    -PfsGroup ECP384 `
    -EncryptionMethod GCMAES256

```


## Configure firewall and other net settings
```
# nat forwarding
# nano /etc/ufw/before.rules:

# insert before filter
*nat
-A POSTROUTING -s 10.1.0.0/16 -o eth0 -m policy --pol ipsec --dir out -j ACCEPT
-A POSTROUTING -s 10.1.0.0/16 -o eth0 -j MASQUERADE
-A POSTROUTING -s 10.0.2.0/24 -o eth0 -m policy --pol ipsec --dir out -j ACCEPT
-A POSTROUTING -s 10.0.2.0/24 -o eth0 -j MASQUERADE
COMMIT
# fragmentation fix
*mangle
-A FORWARD --match policy --pol ipsec --dir in -s 10.1.0.0/16 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
-A FORWARD --match policy --pol ipsec --dir in -s 10.0.2.0/24 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
COMMIT

# ip forwarding
# nano /etc/ufw/sysctl.conf:
net/ipv4/ip_forward=1
net.ipv6.conf.all.forwarding=1

# allow ssh, udp400/500
ufw allow OpenSSH
ufw allow 500/udp
ufw allow 4500/udp

# firewall restart
ufw disable && ufw enable

```

## On premise (windows) add vpn local ip address to routing table to access local gateway without vpn
```
route -p add 10.1.0.0 MASK 255.255.255.0 10.0.1.47
```

- [Good example of site-to-site configuration](https://sites.google.com/site/speccyfan/nastrojka-ipsec-mezdu-oblakom-azure-i-linux)
- [VPN example](https://www.digitalocean.com/community/tutorials/how-to-set-up-an-ikev2-vpn-server-with-strongswan-on-ubuntu-20-04)
- [VPN traffic forwarding](https://wiki.strongswan.org/projects/strongswan/wiki/ForwardingAndSplitTunneling)